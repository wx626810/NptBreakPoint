/*!
    @file       NpHook.cpp

    @brief      services/NpHook：NPT Hook（三态状态机）服务模块�?
    @details    三态状态机（每 CPU 独立）：
      - 状�?A（默认）：GPA �?影子�?（干净拷贝），NX=1。读/写正常，
        取指触发 #NPF�?      - 状�?B（触发中）：GPA �?影子�?（入口为 INT3 的拷贝），NX=0�?        取指执行 INT3 �?#BP VMEXIT �?重定向到跳板�?      - 状�?C（放行中）：GPA �?影子�?，NX=0。跳板执行完序言副本�?        跳回原函数页继续执行（读到的仍是干净字节）�?
      状态转移：
        A --取指@入口--> B --INT3/#BP--> A（跳板接管）
        A --取指@页内--> C（跳板跳回路径）
        C --复位线程 vmmcall--> A

      该模块同时负责：2MB 大页拆分、NPT 叶子修改（原子）、跳板生成�?      影子页管理、Hook 安装/卸载�? */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include <ntimage.h>        // IMAGE_DOS_HEADER / .pdata 目录（展开表构建）
#include "NpDisasm.hpp"
#include "NpReloc.h"
//
// 本文件位于全局命名空间；重定位器（NpReloc）声明于 NptHook 命名空间�?
//
using NptHook::NP_RELOC_MAP;
using NptHook::NP_RELOC_RANGE;
using NptHook::NP_RELOC_RESULT;
using NptHook::NpRelocMapLookup;
using NptHook::NpRelocRelocateBlock;
#include <intrin.h>

//
// 跳板模板布局（与 x64.asm 中 TrampolineTemplate 保持一致）
//
#define TRAMPOLINE_DATA_HOOKFUNC_OFF    0x02
#define TRAMPOLINE_DATA_ORIGINAL_OFF    0x0a
#define TRAMPOLINE_DATA_AFTERPROLOG_OFF 0x12
#define TRAMPOLINE_DATA_PROLOG_OFF      0x1a

//
// 跳回桩：mov rax, imm64 (10B) + jmp rax (2B)
//
#define JUMPBACK_STUB_SIZE 12

//
// 页对齐辅�?
//
#define PAGE_ALIGN_DOWN(x)  ((x) & ~(ULONG_PTR)0xFFF)
#define PAGE_OFFSET(x)      ((x) & 0xFFF)

//
// 全局 Hook 链表
//
static LIST_ENTRY g_HookListHead;
static KSPIN_LOCK g_HookListLock;

//
// 退�?Hook 链表：已从活动链表摘除、但内存尚未释放�?Hook�?
//
// 卸载竞态说明：跳板/影子页可能正被其�?CPU 上的线程执行（NtQuerySystemInformation
// 这类高频目标几乎必然命中），摘除后立即释放会 use-after-free 死机�?
// 因此卸载分两阶段�?
//   阶段一（虚拟化开启时）：摘除 + 恢复恒等映射，Hook 挂入退休链表；
//   阶段二（去虚拟化完成后）：统一释放退休链表内�?—�?此刻无任何线�?
//                             仍在跳板/影子页上，绝对安全�?
//
static LIST_ENTRY g_RetiredHookList;
static KSPIN_LOCK g_RetiredListLock;

//
// �?NptHook.cpp 导出的每处理器数据访问接�?
//
EXTERN_C NTSTATUS NpHvGetProcessorData(_In_ ULONG CpuIndex,
                                       _Out_ PVIRTUAL_PROCESSOR_DATA* OutVpData);
EXTERN_C ULONG NpHvGetProcessorCount(VOID);

//
// 跳板模板（x64.asm 导出�?
//
EXTERN_C VOID TrampolineTemplate(VOID);

// 展开表构建用（ntoskrnl 导出�?
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

// 启动模式保护查询用（wdm 头未声明，本地原型）
extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
EXTERN_C ULONG TrampolineTemplateSize;

//
// �?CPU 配置 Hook 时传给回调的上下�?
//
typedef struct _HOOK_CPU_CONTEXT
{
    PHOOK_INFO Hook;
    ULONG CpuIndex;
} HOOK_CPU_CONTEXT, *PHOOK_CPU_CONTEXT;

/*!
    @brief      在全局链表上查找包含指定虚拟地址�?
Hook�?
    @param[in]  Rip - 客机虚拟地址（取�?断点地址）�?
    @return     命中返回 Hook 指针；否�?
NULL�? */
static
PHOOK_INFO
NpHookFindHookByAddress(
    _In_ ULONG_PTR Rip
    )
{
    PLIST_ENTRY entry;
    PHOOK_INFO hook;

    for (entry = g_HookListHead.Flink;
         entry != &g_HookListHead;
         entry = entry->Flink)
    {
        hook = CONTAINING_RECORD(entry, HOOK_INFO, ListEntry);
        if (hook->Active && (hook->OriginalAddress == Rip))
        {
            return hook;
        }
    }
    return nullptr;
}

/*!
    @brief      在全局链表上查找包含指定页物理地址�?
Hook�?
    @param[in]  PageGpa - 页对齐的客机物理地址（GPA）�?
    @return     命中返回 Hook 指针；否�?
NULL�? */
static
PHOOK_INFO
NpHookFindHookByPage(
    _In_ ULONG_PTR PageGpa
    )
{
    PLIST_ENTRY entry;
    PHOOK_INFO hook;

    PageGpa = PAGE_ALIGN_DOWN(PageGpa);

    for (entry = g_HookListHead.Flink;
         entry != &g_HookListHead;
         entry = entry->Flink)
    {
        hook = CONTAINING_RECORD(entry, HOOK_INFO, ListEntry);
        if (hook->Active && (hook->OriginalPhysical == PageGpa))
        {
            return hook;
        }
    }
    return nullptr;
}

/*!
    @brief      �?
PT 页池中按物理地址查找 PT 页的虚拟地址�?
    @param[in]  Root  - �?
CPU NPT�?    @param[in]  PtPa  - PT 页物理地址�?
    @return     PT 页虚拟地址；未找到返回 NULL�? */
static
PNPT_ENTRY
NpHookFindPtByPhysicalAddress(
    _In_ PNPT_ROOT Root,
    _In_ ULONG_PTR PtPa
    )
{
    for (ULONG i = 0; i < NPTHOOK_MAX_SPLIT_PT_PER_CPU; i++)
    {
        if (Root->PtPhysical[i] == PtPa)
        {
            return Root->Pt[i];
        }
    }
    return nullptr;
}

/*!
    @brief      �?
PT 页池分配一个空�?
PT 页（原子，VMEXIT 安全）�?
    @param[in]  Root  - �?
CPU NPT�?
    @return     PT 页虚拟地址与物理地址；池耗尽返回 FALSE�? */
static
BOOLEAN
NpHookAllocatePtPage(
    _In_ PNPT_ROOT Root,
    _Out_ PNPT_ENTRY* OutPt,
    _Out_ ULONG_PTR* OutPtPa
    )
{
    for (ULONG i = 0; i < NPTHOOK_MAX_SPLIT_PT_PER_CPU; i++)
    {
        ULONG wordIndex = i / 32;
        ULONG bitIndex = i % 32;
        LONG oldValue = InterlockedBitTestAndSet(
                            reinterpret_cast<volatile LONG*>(&Root->PtUsageBitmap[wordIndex]),
                            bitIndex);
        if (oldValue == 0)
        {
            *OutPt = Root->Pt[i];
            *OutPtPa = Root->PtPhysical[i];
            return TRUE;
        }
    }
    return FALSE;
}

/*!
    @brief      释放 PT 页回池（原子）�?
    @param[in]  Root  - �?
CPU NPT�?    @param[in]  PtPa  - PT 页物理地址�? */
static
VOID
NpHookReleasePtPage(
    _In_ PNPT_ROOT Root,
    _In_ ULONG_PTR PtPa
    )
{
    for (ULONG i = 0; i < NPTHOOK_MAX_SPLIT_PT_PER_CPU; i++)
    {
        if (Root->PtPhysical[i] == PtPa)
        {
            ULONG wordIndex = i / 32;
            ULONG bitIndex = i % 32;
            InterlockedBitTestAndReset(
                reinterpret_cast<volatile LONG*>(&Root->PtUsageBitmap[wordIndex]),
                bitIndex);
            return;
        }
    }
}

/*!
    @brief      �?2MB 大页拆分 512 �?4KB 页�?
    @details    先在池中分配 PT 页并按原大页内容填充恒等映射�?                再原子替�?
PDE（InterlockedCompareExchange）。可同时
                从安装路径（PASSIVE）与 VMEXIT 路径（高 IRQL）调用�?
    @param[in]  Root - �?
CPU NPT�?    @param[in]  Pd   - 指向 PDE 的指针�?    @param[in]  OldPde - 原子替换的期望旧值（大页 PDE）�?
    @return     TRUE 拆分成功（或他人已完成）；FALSE 池耗尽�? */
static
BOOLEAN
NpHookSplitLargePage(
    _In_ PNPT_ROOT Root,
    _In_ PNPT_ENTRY Pd,
    _In_ PNPT_ENTRY OldPde
    )
{
    PNPT_ENTRY pt;
    ULONG_PTR ptPa;
    ULONG_PTR largePageGpa;
    NPT_ENTRY newPde;

    //
    // 分配 PT 页�?
//
    if (NpHookAllocatePtPage(Root, &pt, &ptPa) == FALSE)
    {
        return FALSE;
    }

    //
    // 填充 PT：把�?2MB 大页覆盖�?512 �?4KB 页做恒等映射�?
// 保留大页的权限位（Present/Write/User/Accessed/Dirty）�?
//
    largePageGpa = OldPde->Fields.PageFrameNumber << 12;
    for (ULONG k = 0; k < 512; k++)
    {
        pt[k].AsUInt64 = 0;
        pt[k].Fields.Present = OldPde->Fields.Present;
        pt[k].Fields.Write = OldPde->Fields.Write;
        pt[k].Fields.User = OldPde->Fields.User;
        pt[k].Fields.WriteThrough = OldPde->Fields.WriteThrough;
        pt[k].Fields.CacheDisable = OldPde->Fields.CacheDisable;
        pt[k].Fields.Accessed = 1;
        pt[k].Fields.Dirty = 1;
        pt[k].Fields.PageFrameNumber = (largePageGpa >> 12) + k;
        pt[k].Fields.NoExecute = 0;
    }

    //
    // 原子替换 PDE：大�?�?指向 PT�?
//
    newPde.AsUInt64 = 0;
    newPde.Fields.Present = 1;
    newPde.Fields.Write = 1;
    newPde.Fields.User = 1;
    newPde.Fields.Accessed = 1;
    newPde.Fields.PageFrameNumber = ptPa >> 12;

    NPT_ENTRY oldValue;
    oldValue.AsUInt64 = InterlockedCompareExchange64(
                            reinterpret_cast<volatile LONG64*>(Pd),
                            newPde.AsUInt64,
                            OldPde->AsUInt64);
    if (oldValue.AsUInt64 != OldPde->AsUInt64)
    {
        //
        // 其他核心/路径已拆分，释放我们分配�?PT 页�?
//
        NpHookReleasePtPage(Root, ptPa);
    }
    return TRUE;
}

/*!
    @brief      获取指定 GPA �?
NPT 叶子项指针；必要时拆分大页�?
    @details    导出�?
NpHook.h，供 NpBreakPoint 等同层服务复�?                （读�?修改叶子项，�?R 位控制）�?
    @param[in]      Root - �?
CPU NPT�?    @param[in]      Gpa  - 客机物理地址�?    @param[out]     OutLeaf - 叶子项指针�?
    @return     TRUE 成功；FALSE 未映射或拆分失败�? */
_Use_decl_annotations_
BOOLEAN
NpHookGetLeafEntry(
    PNPT_ROOT Root,
    ULONG_PTR Gpa,
    PNPT_ENTRY* OutLeaf
    )
{
    ULONG pml4Index = static_cast<ULONG>((Gpa >> 39) & 0x1FF);
    ULONG pdptIndex = static_cast<ULONG>((Gpa >> 30) & 0x1FF);
    ULONG pdIndex = static_cast<ULONG>((Gpa >> 21) & 0x1FF);
    ULONG ptIndex = static_cast<ULONG>((Gpa >> 12) & 0x1FF);

    //
    // 我们�?NPT 只有 PML4[0] 有效（覆�?512GB）�?
//
    if (pml4Index != 0)
    {
        return FALSE;
    }
    if (!Root->Pml4[pml4Index].Fields.Present)
    {
        return FALSE;
    }
    if (!Root->Pdpt[pdptIndex].Fields.Present)
    {
        return FALSE;
    }

    //
    // PD 层：PDPT[i] 指向 Root->Pd[i]（VA 固定，无需物理反查）�?
//
    PNPT_ENTRY pd = Root->Pd[pdptIndex];
    PNPT_ENTRY pde = &pd[pdIndex];
    if (!pde->Fields.Present)
    {
        return FALSE;
    }

    if (pde->Fields.PatOrPs != 0)
    {
        //
        // 2MB 大页：需要拆分�?
//
        if (NpHookSplitLargePage(Root, pde, pde) == FALSE)
        {
            return FALSE;
        }
        //
        // 拆分�?PDE 已被原子替换（无论是否由我们完成），重新读取�?
//
        pde = &pd[pdIndex];
    }

    //
    // 现在 pde 指向 PT 页，按物理地址反查虚拟地址�?
//
    ULONG_PTR ptPa = pde->Fields.PageFrameNumber << 12;
    PNPT_ENTRY pt = NpHookFindPtByPhysicalAddress(Root, ptPa);
    if (pt == nullptr)
    {
        return FALSE;
    }

    *OutLeaf = &pt[ptIndex];
    return TRUE;
}

/*!
    @brief      把指�?
GPA 的叶子项更新为新的映射（原子），并标�?
TLB 刷新（TlbControl，下�?
VMRUN 时硬件执行）�?
    @details    导出�?
NpHook.h，供 NpBreakPoint（无痕断点）�?                同层服务复用：断�?监视同样通过本函数切换叶子视图�?
    @param[in]  VpData - �?
CPU 数据�?    @param[in]  Gpa    - 客机物理地址（页对齐）�?    @param[in]  Hpa    - 新的主机物理地址�?    @param[in]  NoExecute - 是否�?
NX�?    @param[in]  Writable  - 是否�?
RW�? */
_Use_decl_annotations_
VOID
NpHookSetLeaf(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR Gpa,
    ULONG_PTR Hpa,
    BOOLEAN NoExecute,
    BOOLEAN Writable
    )
{
    PNPT_ENTRY leaf;

    if (NpHookGetLeafEntry(VpData->NptRoot, Gpa, &leaf) == FALSE)
    {
        return;
    }

    NPT_ENTRY newEntry;
    newEntry.AsUInt64 = 0;
    newEntry.Fields.Present = 1;
    newEntry.Fields.Write = Writable ? 1 : 0;
    newEntry.Fields.User = 1;
    newEntry.Fields.Accessed = 1;
    newEntry.Fields.Dirty = 1;
    newEntry.Fields.PageFrameNumber = Hpa >> 12;
    newEntry.Fields.NoExecute = NoExecute ? 1 : 0;

    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(leaf),
                          newEntry.AsUInt64);

    //
    // 标记 TLB 刷新：下�?VMRUN 时刷新本 ASID�?
//
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;
}

/*!
    @brief      分配并初始化跳板�?
    @details    布局：[跳板模板][原函数序言副本][跳回桩]�?                模板�?
RIP 相对引用的数据指针被修补为实际地址�?
    @param[in]  Hook - 已填�?
OriginalAddress/OriginalCode/PrologSize
                       �?
Hook 结构�?
    @return     TRUE 成功�? */
//
// ============================ 方案C：数据访问单步收�?============================
//
// 被_hook 页叶子常�?A 态（NX），任何数据�?写都会触�?#NPF�?
// 处理协议：叶子临时切恒等映射 + �?RFLAGS.TF �?�?这一�?读写指令
// 对真页执行完�?�?#DB 回到 VMM �?恢复 A 态；写则同步全部副本�?
// 暴露窗口严格等于一条指令（纳秒级），且仅限当前核�?
//

#define NPHOOK_MAX_CPU          64
#define NPHOOK_RFLAGS_TF        0x100UL

static PHOOK_INFO g_DataStepHook[NPHOOK_MAX_CPU];       // NULL = 本核无挂�?
static BOOLEAN g_DataStepIsWrite[NPHOOK_MAX_CPU];

_Use_decl_annotations_
BOOLEAN
NpHookHandleDebugStep(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    PHOOK_INFO hook;
    ULONG cpu;

    cpu = VpData->CpuIndex;
    if (cpu >= NPHOOK_MAX_CPU)
    {
        return FALSE;
    }

    hook = g_DataStepHook[cpu];
    if (hook == nullptr)
    {
        return FALSE;                       // 非本框架的数据单�?
}

    //
    // 写违例：真页已被这条写指令更新（恒等视图），把新内容同步到全部副本�?
// S1 同步后需重打 INT3�?
//
    if (g_DataStepIsWrite[cpu])
    {
        PUCHAR realPage = reinterpret_cast<PUCHAR>(
            PAGE_ALIGN_DOWN(hook->OriginalAddress));

        RtlCopyMemory(hook->ShadowPage0, realPage, PAGE_SIZE);
        RtlCopyMemory(hook->ShadowPage1, realPage, PAGE_SIZE);
        static_cast<PUCHAR>(hook->ShadowPage1)[hook->PageOffset] = 0xCC;
        if (hook->CloneVA != nullptr)
        {
            RtlCopyMemory(hook->CloneVA, realPage, PAGE_SIZE);
        }
    }

    //
    // 收口：回 A 态（S0 + NX），�?TF，解除挂起�?
//
    NpHookSetLeaf(VpData,
                  hook->OriginalPhysical,
                  hook->ShadowPage0PA,
                  TRUE,
                  TRUE);
    VpData->GuestVmcb.StateSaveArea.Rflags &= ~NPHOOK_RFLAGS_TF;
    g_DataStepHook[cpu] = nullptr;
    return TRUE;
}

//
// 注册表适配器：VMEXIT 注册表要求双参数签名�?
//
static
BOOLEAN
NPHOOK_VMEXIT_HANDLER_COMPAT(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    UNREFERENCED_PARAMETER(GuestContext);
    return NpHookHandleDebugStep(VpData);
}

/*!
    @brief      数据�?写违例处理（方案C）�?
    @details    被_hook 页叶子常�?
NX，任何数据访问都会触�?#NPF�?                处理：临时切恒等映射 + �?
TF，让这一条读写指令对真页
                执行完成后由 #DB 收口。窗�?= 一条指令，仅限当前核�?
    @return     TRUE 已处理；FALSE �?
Hook 页（回落原逻辑）�? */
_Use_decl_annotations_
BOOLEAN
NpHookHandleDataFault(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR FaultGpa,
    ULONG FaultErrorCode)
{
    PHOOK_INFO hook;
    KIRQL oldIrql;
    ULONG cpu;

    if ((FaultErrorCode & NPF_ERROR_IFETCH) != 0)
    {
        return FALSE;                       // 取指走 HandleNpf
    }

    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    hook = NpHookFindHookByPage(FaultGpa);
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    if (hook == nullptr || !hook->Active)
    {
        return FALSE;
    }

    cpu = VpData->CpuIndex;
    if (cpu >= NPHOOK_MAX_CPU)
    {
        //
        // CPU 编号越界（不应发生）：退化为恒等自愈�?
// 该页此后保持恒等直到复位线程兜底 —�?记录日志定位�?
//
        NpHookRestoreIdentity(VpData, FaultGpa & ~static_cast<ULONG_PTR>(0xFFF));
        NpHvLogPrint("[hook] data fault on CPU%u overflow, identity fallback\n", cpu);
        return TRUE;
    }

    g_DataStepHook[cpu] = hook;
    g_DataStepIsWrite[cpu] = ((FaultErrorCode & NPF_ERROR_WRITE) != 0);

    //
    // 开门一条指令：恒等映射（RWX�?TF。下一条指令执行完 #DB 即回�?
//
    NpHookRestoreIdentity(VpData, FaultGpa & ~static_cast<ULONG_PTR>(0xFFF));
    VpData->GuestVmcb.StateSaveArea.Rflags |= NPHOOK_RFLAGS_TF;
    return TRUE;
}

//
// ============================ 方案C：克隆页展开�?============================
//
// 内核未导出动态展开�?API（本�?ntoskrnl 已核实）。替代方案：�?
// RtlLookupFunctionEntry 本体做一次方案C 元钩子——查表请求落在克隆区间时�?
// 返回预构建的重定位展开条目（ImageBase=克隆基址）�?
//
// 精确性边界：仅收�?UNWIND_INFO 无语言处理器标志（EH/UH）且�? 无 CHAININFO

// 的帧——这类帧的展开不引�?ImageBase 之外的任何地址，克隆基址�?作 ImageBase

// 完全自洽。带处理器的帧放弃精确化（维持旧的不精确回退），避免错误寻址�?
//
// PatchView 用户态补丁克隆的展开�?NpPvMatchClone（后文定义）接入本回调�?
static BOOLEAN NpPvMatchClone(
    _In_ ULONG_PTR ControlPc,
    _Out_ PVOID* EntryOut,
    _Out_ ULONG64* ImageBaseOut);
//

typedef struct _NP_UNWIND_INFO {
    UCHAR Version : 3;
    UCHAR Flags   : 5;                  // bit0 EH, bit1 UH, bit2 CHAININFO
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR Frame;                        // FrameRegister:4 | FrameOffset:4
} NP_UNWIND_INFO, *PNP_UNWIND_INFO;

#define NPHOOK_UNW_FLAG_EHANDLER   0x01
#define NPHOOK_UNW_FLAG_UHANDLER   0x02
#define NPHOOK_UNW_FLAG_CHAININFO  0x04
#define NPHOOK_UNW_FAIL            0xFFFFFFFF

static PHOOK_INFO g_UnwindMasterHook = nullptr;
static BOOLEAN g_UnwindMasterBusy = FALSE;
static volatile LONG g_CloneActiveCount = 0;

//
// 展开 INFO 拷贝�?blob（含 codes；CHAININFO 递归一层并要求链目标同页）�?
// 返回 blob 内偏移；FAIL 表示�?INFO 含语言处理�?越界链——调用方放弃整帧�?
//
static
ULONG
NpHookCopyUnwindInfo(
    _In_ PUCHAR Blob,
    _In_ ULONG BlobCap,
    _Inout_ PULONG Used,
    _In_ PUCHAR ModuleBase,
    _In_ ULONG PageRvaLo,
    _In_ ULONG ModuleRva,
    _Inout_ ULONG* CacheSrc,
    _Inout_ ULONG* CacheNew,
    _Inout_ ULONG* CacheN
    )
{
    PUCHAR info;
    PNP_UNWIND_INFO hdr;
    ULONG len, codesPad, pre, newOff, oldUsed, k;

    for (k = 0; k < *CacheN; k++)
    {
        if (CacheSrc[k] == ModuleRva)
        {
            return CacheNew[k];         // 已拷贝过（链共享场景�?
}
    }

    info = ModuleBase + ModuleRva;
    oldUsed = *Used;

    __try
    {
        hdr = (PNP_UNWIND_INFO)info;
        if (hdr->Version != 1 && hdr->Version != 2)
        {
            return NPHOOK_UNW_FAIL;
        }
        if (hdr->Flags & (NPHOOK_UNW_FLAG_EHANDLER | NPHOOK_UNW_FLAG_UHANDLER))
        {
            return NPHOOK_UNW_FAIL;     // 语言处理器寻址不可达，放弃
        }
        codesPad = ((hdr->CountOfCodes + 1) & ~1) * 2;
        len = sizeof(NP_UNWIND_INFO) + codesPad;
        pre = len;
        if (hdr->Flags & NPHOOK_UNW_FLAG_CHAININFO)
        {
            len = (len + 3) & ~3;
            len += sizeof(RUNTIME_FUNCTION);
        }
        if (*Used + len > BlobCap)
        {
            return NPHOOK_UNW_FAIL;
        }
        RtlCopyMemory(Blob + *Used, info, len);
        newOff = *Used;
        *Used += (len + 3) & ~3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *Used = oldUsed;
        return NPHOOK_UNW_FAIL;
    }

    if (hdr->Flags & NPHOOK_UNW_FLAG_CHAININFO)
    {
        //
        // 链目标函数必须也在本页内（funclet �?父函数的典型形态）�?
// 否则放弃整帧。链�?RUNTIME_FUNCTION �?RVA 改写为页内偏移�?
//
        PRUNTIME_FUNCTION crf = (PRUNTIME_FUNCTION)(Blob + newOff +
            ((pre + 3) & ~3));
        if (crf->BeginAddress < PageRvaLo ||
            crf->EndAddress > PageRvaLo + NP_RELOC_BLOCK_SIZE)
        {
            *Used = oldUsed;
            return NPHOOK_UNW_FAIL;
        }
        crf->BeginAddress -= PageRvaLo;
        crf->EndAddress -= PageRvaLo;
        ULONG sub = NpHookCopyUnwindInfo(Blob, BlobCap, Used, ModuleBase,
                                         PageRvaLo, crf->UnwindData,
                                         CacheSrc, CacheNew, CacheN);
        if (sub == NPHOOK_UNW_FAIL)
        {
            *Used = oldUsed;
            return NPHOOK_UNW_FAIL;
        }
        crf->UnwindData = PAGE_SIZE + sub;
    }

    if (*CacheN < 32)
    {
        CacheSrc[*CacheN] = ModuleRva;
        CacheNew[*CacheN] = newOff;
        (*CacheN)++;
    }
    return newOff;
}

//
// 为克隆页构建展开条目数组。返回条目数�? = 不可精确，回退旧行为）�?
//
static
ULONG
NpHookBuildCloneUnwind(
    _In_ PHOOK_INFO Hook,
    _In_ PUCHAR PageVA,
    _In_ ULONG64 ImageBase
    )
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nth;
    IMAGE_DATA_DIRECTORY* dir;
    PRUNTIME_FUNCTION pfBase;
    ULONG n, pageRvaLo, hi, selIdx[32], selCnt = 0, i, added = 0;
    ULONG cacheSrc[32], cacheNew[32], cacheN = 0;
    PUCHAR blob;

    dos = (IMAGE_DOS_HEADER*)ImageBase;
    __try
    {
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }
        nth = RtlImageNtHeader((PVOID)ImageBase);
        if (nth == nullptr)
        {
            return 0;
        }
        dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (dir->Size < sizeof(RUNTIME_FUNCTION))
        {
            return 0;
        }

        pfBase = (PRUNTIME_FUNCTION)(ImageBase + dir->VirtualAddress);
        n = dir->Size / sizeof(RUNTIME_FUNCTION);
        pageRvaLo = static_cast<ULONG>(PageVA - (PUCHAR)ImageBase);
        hi = pageRvaLo + NP_RELOC_BLOCK_SIZE;

        //
        // 展开 INFO blob 位于克隆块末尾页（代码区之后，互不覆盖）�?
//
        blob = static_cast<PUCHAR>(Hook->CloneVA) + NP_RELOC_MAX_OUT;

        for (i = 0; i < n && pfBase[i].BeginAddress < hi && selCnt < 32; i++)
        {
            if (pfBase[i].EndAddress <= pageRvaLo)
            {
                continue;
            }
            //
            // 预检语言处理器标志：任一候选带处理器即整体放弃（保�?
// ImageBase=克隆基址的自洽性，见文件头说明）�?
//
            PNP_UNWIND_INFO h2 = (PNP_UNWIND_INFO)(ImageBase + pfBase[i].UnwindData);
            if (h2->Flags & (NPHOOK_UNW_FLAG_EHANDLER | NPHOOK_UNW_FLAG_UHANDLER |
                             NPHOOK_UNW_FLAG_CHAININFO))
            {
                NpHvLogPrint("[hook] unwind: page 0x%p has SEH frame, "
                             "skip precise unwind\n", PageVA);
                return 0;
            }
            selIdx[selCnt++] = i;
        }
        if (selCnt == 0)
        {
            return 0;
        }

        PRUNTIME_FUNCTION arr = static_cast<PRUNTIME_FUNCTION>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED,
                            selCnt * sizeof(RUNTIME_FUNCTION), 'kpoN'));
        if (arr == nullptr)
        {
            return 0;
        }
        ULONG used = 0;

        for (i = 0; i < selCnt; i++)
        {
            const RUNTIME_FUNCTION* src = &pfBase[selIdx[i]];
            ULONG infoOff = NpHookCopyUnwindInfo(
                blob, PAGE_SIZE, &used, (PUCHAR)ImageBase, pageRvaLo,
                src->UnwindData, cacheSrc, cacheNew, &cacheN);
            if (infoOff == NPHOOK_UNW_FAIL)
            {
                continue;                   // 该帧退化为不精�?
}
            //
            // 条目区间映射到重定位后布局（Begin/End 均为克隆偏移）�?
//
            ULONG b = (src->BeginAddress > pageRvaLo)
                ?
src->BeginAddress - pageRvaLo : 0;
            ULONG e = (src->EndAddress < pageRvaLo + NP_RELOC_BLOCK_SIZE)
                ?
src->EndAddress - pageRvaLo : NP_RELOC_BLOCK_SIZE;
            if (e <= b)
            {
                continue;
            }
            arr[added].BeginAddress = NpRelocMapLookup(
                static_cast<const NP_RELOC_MAP*>(Hook->CloneMap),
                Hook->CloneMapCount, b);
            arr[added].EndAddress = NpRelocMapLookup(
                static_cast<const NP_RELOC_MAP*>(Hook->CloneMap),
                Hook->CloneMapCount, e);
            arr[added].UnwindData = NP_RELOC_MAX_OUT + infoOff;
            added++;
        }

        if (added == 0)
        {
            ExFreePoolWithTag(arr, 'kpoN');
            return 0;
        }

        Hook->CloneUnwind = arr;
        Hook->CloneUnwindCount = added;
        NpHvLogPrint("[hook] clone unwind: %lu entries @ clone 0%p\n",
                     added, Hook->CloneVA);
        return added;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (Hook->CloneUnwind != nullptr)
        {
            ExFreePoolWithTag(Hook->CloneUnwind, 'kpoN');
            Hook->CloneUnwind = nullptr;
            Hook->CloneUnwindCount = 0;
        }
        return 0;
    }
}

//
// 元钩子回调：RtlLookupFunctionEntry(ControlPc@Rcx, ImageBase@Rdx, ...)
// 命中克隆区间 �?返回重定位条目指�?+ ImageBase=克隆基址�?
//
static
BOOLEAN
NpHookUnwindLookupCb(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    PLIST_ENTRY entry;
    PHOOK_INFO hook;
    KIRQL oldIrql;
    ULONG_PTR pc;
    BOOLEAN hit = FALSE;

    //
    // PatchView 用户态补丁克隆优先匹配（与内核克隆区间互不重叠）�?
//
    PVOID pvEntry = nullptr;
    ULONG64 pvImageBase = 0;
    if (NpPvMatchClone(Ctx->Rcx, &pvEntry, &pvImageBase))
    {
        Ctx->Rax = reinterpret_cast<ULONG_PTR>(pvEntry);
        *reinterpret_cast<PULONG_PTR>(Ctx->Rdx) = pvImageBase;
        return TRUE;
    }

    if (g_CloneActiveCount == 0)
    {
        return FALSE;
    }

    pc = Ctx->Rcx;

    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    for (entry = g_HookListHead.Flink;
         entry != &g_HookListHead && !hit;
         entry = entry->Flink)
    {
        hook = CONTAINING_RECORD(entry, HOOK_INFO, ListEntry);
        if (!hook->Active || hook->CloneUnwindCount == 0 || hook->CloneVA == nullptr)
        {
            continue;
        }
        if (pc < reinterpret_cast<ULONG_PTR>(hook->CloneVA) ||
            pc >= reinterpret_cast<ULONG_PTR>(hook->CloneVA) + hook->CloneCodeLen)
        {
            continue;
        }

        ULONG off = static_cast<ULONG>(
            pc - reinterpret_cast<ULONG_PTR>(hook->CloneVA));
        for (ULONG j = 0; j < hook->CloneUnwindCount; j++)
        {
            if (off >= hook->CloneUnwind[j].BeginAddress &&
                off < hook->CloneUnwind[j].EndAddress)
            {
                *reinterpret_cast<PULONG_PTR>(Ctx->Rdx) =
                    reinterpret_cast<ULONG_PTR>(hook->CloneVA);
                Ctx->Rax =
                    reinterpret_cast<ULONG_PTR>(&hook->CloneUnwind[j]);
                hit = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);
    return hit;
}

//
// 惰性安装元钩子（首次克隆创建时调用一次）�?
//
static
VOID
NpHookEnsureUnwindMaster(
    VOID
    )
{
    UNICODE_STRING name;
    PVOID routine;
    NTSTATUS status;

    if (g_UnwindMasterHook != nullptr || g_UnwindMasterBusy)
    {
        return;
    }
    g_UnwindMasterBusy = TRUE;

    RtlInitUnicodeString(&name, L"RtlLookupFunctionEntry");
    routine = MmGetSystemRoutineAddress(&name);
    if (routine != nullptr)
    {
        status = NpHookInstallHook(reinterpret_cast<ULONG_PTR>(routine),
                                   NpHookUnwindLookupCb,
                                   &g_UnwindMasterHook);
        NpHvLogPrint("[hook] unwind master: RtlLookupFunctionEntry %p -> "
                     "0x%08x\n", routine, status);
        if (!NT_SUCCESS(status))
        {
            g_UnwindMasterHook = nullptr;   // 失败可重�?
}
    }
    g_UnwindMasterBusy = FALSE;
}

//
//
// ============================ 方案C：PatchView（用户态隐匿补丁，双页组） ============================
//
// 语义矩阵�?
//   执行（任何线程）        �?克隆块（补丁后字节）
//   数据读：安装�?查看�?  �?克隆帧（视图自洽，看到自己改的）
//   数据读：其他进程/内核   �?真页（原始字节，CRC 通过�?
//   数据写：查看�?         �?落克隆（累积为补丁的一部分�?
//   数据写：受害�?外部     �?落真页（公开变更），克隆同步时保留分歧偏�?
//
// 双页组模型：一个视图覆盖连�?8KB VA 窗口 [VaLo, VaLo+0x2000)�?
// 16KB 对齐块布局�?
//   +0x0000 CleanLo   +0x1000 CleanHi    （武装视图内容载体）
//   +0x2000 CloneLo   +0x3000 CloneHi    （执�?观察者视图，含补丁字节）
// 武装态：两页叶子 Present=0 —�?取指与数据访问同时陷�?#NPF�?
// �?VMM 按取�?数据与观察者身份分别裁决。执行重定向公式�?
//   RIP := Base + 0x2000 + (FaultRip - VaLo)
// 函数体跨页时执行流在克隆块内无缝连续�?
//

#define NPPV_MAX            8       // 补丁组上限
#define NPPV_MAX_VIEWERS    4

typedef struct _NPPV_ENTRY {
    LIST_ENTRY Retired;                         // 卸载退休链
    BOOLEAN Active;
    ULONG VictimPid;
    ULONG_PTR VaLo;                             // 组起始 VA（低页基址，页对齐）
    ULONG_PTR GpaLo;                            // 低页 GPA
    ULONG_PTR GpaHi;                            // 高页 GPA（= 高页无效时）
    PVOID OrigVa;                               // = VaLo
    PUCHAR Base;                                // 对齐块基址（16KB）
    PVOID Raw;                                  // 原始分配指针
    ULONG ViewerPids[NPPV_MAX_VIEWERS];
    PMDL PageMdl;                               // 页面锁定 MDL（防换页漂移）
    //
    // 精确异常展开：目标模块 .pdata 条目【原样】池拷贝 + 模块基址。
    // 元钩子命中克隆区间时，按"折算模块 RVA"检索并返回条目指针与真实
    // 模块基址 —— 展开器读取的全部信息都指向真实模块内存，
    // 含 C++ EH 处理器在内保真度 100%。
    //
    PRUNTIME_FUNCTION Unwind;                   // 原样拷贝的条目数组（池内）
    ULONG UnwindCount;
    ULONG64 UnwindImageBase;                    // 所在模块基址
    ULONG UnwindRvaLo;                          // VaLo 的模块 RVA
} NPPV_ENTRY, *PNPPV_ENTRY;

static NPPV_ENTRY g_Pv[NPPV_MAX];
static LIST_ENTRY g_PvRetiredList;
static KSPIN_LOCK g_PvRetiredLock;
static KSPIN_LOCK g_PvLock;
static volatile LONG g_PvCreating = 0;

static struct {
    PNPPV_ENTRY Pv;
    ULONG PageIdx;                              // 0=低页 1=高页
    BOOLEAN Viewer;
    BOOLEAN IsWrite;
    BOOLEAN HadTf;                              // 进入前 TF 已置（调试器单步中）
} g_PvStep[NPHOOK_MAX_CPU];

// ---- 叶子原语 ------------------------------------------------------------------

static
VOID
PvOpenFrame(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR Gpa,
    _In_ ULONG_PTR Hpa
    )
{
    NpHookSetLeaf(VpData, Gpa, Hpa, FALSE, TRUE);
}

static
BOOLEAN
PvIsViewer(
    _In_ PNPPV_ENTRY Pv,
    _In_ ULONG Pid
    )
{
    for (ULONG i = 0; i < NPPV_MAX_VIEWERS; i++)
    {
        if (Pv->ViewerPids[i] == Pid && Pid != 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static
VOID
PvAddViewer(
    _In_ PNPPV_ENTRY Pv,
    _In_ ULONG Pid
    )
{
    if (PvIsViewer(Pv, Pid) || Pid == 0)
    {
        return;
    }
    for (ULONG i = 0; i < NPPV_MAX_VIEWERS; i++)
    {
        if (Pv->ViewerPids[i] == 0)
        {
            Pv->ViewerPids[i] = Pid;
            return;
        }
    }
}

static
PNPPV_ENTRY
PvFindGroupByGpa(
    ULONG_PTR Gpa
    )
{
    for (ULONG i = 0; i < NPPV_MAX; i++)
    {
        if (!g_Pv[i].Active || g_Pv[i].GpaLo == 0)
        {
            continue;
        }
        ULONG_PTR hi = g_Pv[i].GpaHi ?
                       g_Pv[i].GpaHi : g_Pv[i].GpaLo;
        if (Gpa == g_Pv[i].GpaLo || Gpa == hi)
        {
            return &g_Pv[i];
        }
    }
    return nullptr;
}

//
// 元钩子检索：ControlPc 落在某补丁克隆区间时返回该模块的原始
// .pdata 条目与真实模块基址 —�?展开语义与未打补丁完全一致�?
//
BOOLEAN
NpPvMatchClone(
    _In_ ULONG_PTR ControlPc,
    _Out_ PVOID* EntryOut,
    _Out_ ULONG64* ImageBaseOut
    )
{
    KIRQL oldIrql;
    BOOLEAN hit = FALSE;

    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    for (ULONG i = 0; i < NPPV_MAX && !hit; i++)
    {
        PNPPV_ENTRY pv = &g_Pv[i];
        if (!pv->Active || pv->UnwindCount == 0 || pv->VaLo == 0)
        {
            continue;
        }
        if (ControlPc < pv->VaLo ||
            ControlPc >= pv->VaLo + 0x2000)
        {
            continue;
        }

        //
        // 克隆偏移折算回模�?RVA 等价点，再在原样拷贝条目中定位�?
//
        ULONG rvaE = pv->UnwindRvaLo +
                     static_cast<ULONG>(ControlPc - pv->VaLo);
        for (ULONG j = 0; j < pv->UnwindCount; j++)
        {
            if (rvaE >= pv->Unwind[j].BeginAddress &&
                rvaE < pv->Unwind[j].EndAddress)
            {
                *EntryOut = const_cast<PRUNTIME_FUNCTION>(&pv->Unwind[j]);
                *ImageBaseOut = pv->UnwindImageBase;
                hit = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_PvLock, oldIrql);
    return hit;
}

// ---- VMEXIT 处理�?-------------------------------------------------------------

_Use_decl_annotations_
BOOLEAN
NpPatchViewHandleNpf(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR FaultGpa,
    ULONG_PTR FaultRip,
    ULONG ErrorCode)
{
    PNPPV_ENTRY pv;
    KIRQL oldIrql;

    if ((ErrorCode & NPF_ERROR_IFETCH) == 0)
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    pv = PvFindGroupByGpa(FaultGpa);
    KeReleaseSpinLock(&g_PvLock, oldIrql);

    if (pv == nullptr || !pv->Active)
    {
        return FALSE;
    }

    VpData->GuestVmcb.StateSaveArea.Rip =
        reinterpret_cast<ULONG_PTR>(pv->Base) + 0x2000 +
        (FaultRip - pv->VaLo);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
NpPatchViewHandleDataFault(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR FaultGpa,
    ULONG FaultErrorCode)
{
    PNPPV_ENTRY pv;
    KIRQL oldIrql;
    ULONG cpu, pageIdx;

    if ((FaultErrorCode & NPF_ERROR_IFETCH) != 0)
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    pv = PvFindGroupByGpa(FaultGpa);
    KeReleaseSpinLock(&g_PvLock, oldIrql);

    if (pv == nullptr || !pv->Active)
    {
        return FALSE;
    }

    cpu = VpData->CpuIndex;
    if (cpu >= NPHOOK_MAX_CPU)
    {
        NpHookRestoreIdentity(VpData, FaultGpa & ~static_cast<ULONG_PTR>(0xFFF));
        NpHookRestoreIdentity(VpData,
            (FaultGpa & ~static_cast<ULONG_PTR>(0xFFF)) + PAGE_SIZE);
        return TRUE;
    }

    pageIdx = (FaultGpa == pv->GpaHi) ? 1 : 0;
    BOOLEAN viewer = PvIsViewer(pv, static_cast<ULONG>(
        reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())));

    g_PvStep[cpu].Pv = pv;
    g_PvStep[cpu].PageIdx = pageIdx;
    g_PvStep[cpu].Viewer = viewer;
    g_PvStep[cpu].IsWrite = ((FaultErrorCode & NPF_ERROR_WRITE) != 0);
    g_PvStep[cpu].HadTf =
        (VpData->GuestVmcb.StateSaveArea.Rflags & 0x100UL) != 0;

    if (viewer)
    {
        PvOpenFrame(VpData, FaultGpa,
                    reinterpret_cast<ULONG_PTR>(pv->Base) + 0x2000 +
                        (pageIdx * PAGE_SIZE));
    }
    else
    {
        NpHookRestoreIdentity(VpData, FaultGpa & ~static_cast<ULONG_PTR>(0xFFF));
    }

    VpData->GuestVmcb.StateSaveArea.Rflags |= 0x100UL;
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
NpPatchViewHandleDebugStep(
    PVIRTUAL_PROCESSOR_DATA VpData)
{
    PNPPV_ENTRY pv;
    ULONG cpu, pageIdx;
    BOOLEAN viewer, isWrite, hadTf;

    cpu = VpData->CpuIndex;
    if (cpu >= NPHOOK_MAX_CPU)
    {
        return FALSE;
    }
    pv = g_PvStep[cpu].Pv;
    if (pv == nullptr)
    {
        return FALSE;
    }
    pageIdx = g_PvStep[cpu].PageIdx;
    viewer = g_PvStep[cpu].Viewer;
    isWrite = g_PvStep[cpu].IsWrite;
    hadTf = g_PvStep[cpu].HadTf;

    if (isWrite && !viewer)
    {
        ULONG_PTR srcGpa = (pageIdx == 0) ?
pv->GpaLo : pv->GpaHi;
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = static_cast<LONGLONG>(srcGpa);
        PVOID pm = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
        if (pm != nullptr)
        {
            PUCHAR clean = static_cast<PUCHAR>(pv->Base) + (pageIdx * PAGE_SIZE);
            PUCHAR clone = static_cast<PUCHAR>(pv->Base) + 0x2000 +
                           (pageIdx * PAGE_SIZE);
            PUCHAR real = static_cast<PUCHAR>(pm);
            __try
            {
                for (ULONG i = 0; i < PAGE_SIZE; i++)
                {
                    if (clone[i] == clean[i])
                    {
                        clone[i] = real[i];
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            MmUnmapIoSpace(pm, PAGE_SIZE);
        }
    }

    {
        PVIRTUAL_PROCESSOR_DATA vp = nullptr;
        if (NT_SUCCESS(NpHvGetProcessorData(cpu, &vp)) && vp != nullptr)
        {
            PNPT_ENTRY leaf;
            if (NpHookGetLeafEntry(vp->NptRoot,
                    (pageIdx == 0) ?
pv->GpaLo : pv->GpaHi, &leaf))
            {
                NPT_ENTRY e = *leaf;
                e.Fields.Present = 0;
                InterlockedExchange64(
                    reinterpret_cast<volatile LONG64*>(leaf), e.AsUInt64);
                vp->GuestVmcb.ControlArea.TlbControl =
                    TLB_CONTROL_FLUSH_ASID;
            }
        }
    }

    g_PvStep[cpu].Pv = nullptr;

    if (hadTf)
    {
        return FALSE;
    }

    VpData->GuestVmcb.StateSaveArea.Rflags &= ~0x100UL;
    return TRUE;
}

// ---- 展开（用户态克隆帧的精确异常展开�?-----------------------------------------

static
ULONG64
PvFindImageBaseAttached(
    _In_ PVOID UserVa
    )
{
    PUCHAR p = reinterpret_cast<PUCHAR>(
        reinterpret_cast<ULONG_PTR>(UserVa) & ~static_cast<ULONG_PTR>(0xFFF));
    for (ULONG i = 0; i < 1024; i++, p -= PAGE_SIZE)
    {
        __try
        {
            if (MmIsAddressValid(p) && p[0] == 'M' && p[1] == 'Z')
            {
                LONG eLfanew = *(LONG*)(p + 0x3C);
                if (eLfanew > 0 && eLfanew < 0x1000)
                {
                    PUCHAR pe = p + eLfanew;
                    if (MmIsAddressValid(pe) && pe[0] == 'P' && pe[1] == 'E')
                    {
                        return reinterpret_cast<ULONG64>(p);
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }
    return 0;
}

//
// 收集覆盖两页窗口的目标模�?.pdata 条目【原样】拷贝进池�?
//
static
ULONG
NpPvCollectUnwind(
    _In_ PNPPV_ENTRY Pv,
    _In_ ULONG64 ImageBase,
    _Out_ ULONG* RvaLoOut
    )
{
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
    IMAGE_NT_HEADERS* nth;
    IMAGE_DATA_DIRECTORY* dir;
    PRUNTIME_FUNCTION pf;
    ULONG n, rvaLo, rvaHi, cnt = 0;
    PRUNTIME_FUNCTION copy;

    __try
    {
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }
        nth = RtlImageNtHeader(reinterpret_cast<PVOID>(ImageBase));
        if (nth == nullptr)
        {
            return 0;
        }
        dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (dir->Size < sizeof(RUNTIME_FUNCTION))
        {
            return 0;
        }
        pf = reinterpret_cast<PRUNTIME_FUNCTION>(ImageBase + dir->VirtualAddress);
        n = dir->Size / sizeof(RUNTIME_FUNCTION);
        rvaLo = static_cast<ULONG>(Pv->VaLo - ImageBase);
        rvaHi = rvaLo + 0x2000;

        for (ULONG i = 0; i < n && pf[i].BeginAddress < rvaHi; i++)
        {
            if (pf[i].EndAddress <= rvaLo)
            {
                continue;
            }
            cnt++;
        }
        if (cnt == 0 || cnt > 64)
        {
            return 0;
        }

        copy = static_cast<PRUNTIME_FUNCTION>(ExAllocatePool2(
            POOL_FLAG_NON_PAGED, cnt * sizeof(RUNTIME_FUNCTION), 'VtPp'));
        if (copy == nullptr)
        {
            return 0;
        }
        ULONG k = 0;
        for (ULONG i = 0; i < n && k < cnt; i++)
        {
            if (pf[i].EndAddress <= rvaLo)
            {
                continue;
            }
            if (pf[i].BeginAddress >= rvaHi)
            {
                break;
            }
            copy[k++] = pf[i];                  // 原样拷贝（原始模块 RVA）
        }

        Pv->Unwind = copy;
        Pv->UnwindCount = k;
        *RvaLoOut = rvaLo;
        return k;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (Pv->Unwind != nullptr)
        {
            ExFreePoolWithTag(Pv->Unwind, 'VtPp');
            Pv->Unwind = nullptr;
            Pv->UnwindCount = 0;
        }
        return 0;
    }
}

// ---- 安装 / 写入应用 -----------------------------------------------------------

//
// 武装：组内两页叶子全�?Present=0（保�?PFN/权限位以便诊断与恢复）�?
// �?CPU 叶子独立，需对各核分别执行（安装路径逐核调用）�?
//
static
VOID
NpPvArmGroup(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PNPPV_ENTRY Pv
    )
{
    PNPT_ENTRY leaf;

    if (NpHookGetLeafEntry(VpData->NptRoot, Pv->GpaLo, &leaf))
    {
        NPT_ENTRY e = *leaf;
        e.Fields.Present = 0;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(leaf), e.AsUInt64);
    }
    if (Pv->GpaHi != 0 &&
        NpHookGetLeafEntry(VpData->NptRoot, Pv->GpaHi, &leaf))
    {
        NPT_ENTRY e = *leaf;
        e.Fields.Present = 0;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(leaf), e.AsUInt64);
    }
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;
}

BOOLEAN
NpPvApplyWrite(
    ULONG VictimPid,
    ULONG WriterPid,
    ULONG_PTR Va,
    PVOID Buffer,
    ULONG Length)
{
    PUCHAR pageVa;
    ULONG_PTR gpaLo = 0, gpaHi = 0;
    PNPPV_ENTRY pv = nullptr;
    PEPROCESS proc = nullptr;
    KIRQL oldIrql;
    UCHAR tmp[NPHV_PATCH_MAX_LEN];
    ULONG unwindCount = 0;
    ULONG unwindRvaLo = 0;
    ULONG64 imgBase = 0;

    if (Length == 0 || Length > NPHV_PATCH_MAX_LEN)
    {
        return FALSE;
    }
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }

    pageVa = reinterpret_cast<PUCHAR>(PAGE_ALIGN_DOWN(Va));

    __try
    {
        RtlCopyMemory(tmp, Buffer, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    if (!NT_SUCCESS(PsLookupProcessByProcessId(
            ULongToHandle(VictimPid), &proc)) || proc == nullptr)
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    for (ULONG i = 0; i < NPPV_MAX; i++)
    {
        if (g_Pv[i].Active && g_Pv[i].VictimPid == VictimPid &&
            Va >= reinterpret_cast<ULONG_PTR>(g_Pv[i].OrigVa) &&
            Va < reinterpret_cast<ULONG_PTR>(g_Pv[i].OrigVa) + 0x2000)
        {
            pv = &g_Pv[i];
            break;
        }
    }
    KeReleaseSpinLock(&g_PvLock, oldIrql);

    if (pv == nullptr)
    {
        while (InterlockedCompareExchange(&g_PvCreating, 1, 0) != 0)
        {
            LARGE_INTEGER d;
            d.QuadPart = -100000;
            KeDelayExecutionThread(KernelMode, FALSE, &d);
        }

        KeAcquireSpinLock(&g_PvLock, &oldIrql);
        for (ULONG i = 0; i < NPPV_MAX; i++)
        {
            if (g_Pv[i].Active && g_Pv[i].VictimPid == VictimPid &&
                Va >= reinterpret_cast<ULONG_PTR>(g_Pv[i].OrigVa) &&
                Va < reinterpret_cast<ULONG_PTR>(g_Pv[i].OrigVa) + 0x2000)
            {
                pv = &g_Pv[i];
                break;
            }
        }
        KeReleaseSpinLock(&g_PvLock, oldIrql);
    }

    BOOLEAN createdHere = FALSE;
    BOOLEAN unwindOk = FALSE;

    if (pv == nullptr)
    {
        KAPC_STATE apcState;
        PUCHAR raw = static_cast<PUCHAR>(ExAllocatePool2(
            POOL_FLAG_NON_PAGED, 0x8000, 'VtPp'));          // 32KB
        if (raw == nullptr)
        {
            InterlockedExchange(&g_PvCreating, 0);
            ObDereferenceObject(proc);
            return FALSE;
        }
        PUCHAR aligned = reinterpret_cast<PUCHAR>(
            (reinterpret_cast<ULONG_PTR>(raw) + 0x3FFF) &
            ~static_cast<ULONG_PTR>(0x3FFF));               // 16KB 对齐

        //
        // 附着目标上下文（PASSIVE）：解析两页 GPA、填�?CLEAN/CLONE�?
// 登记槽位，并在附着内完成展开表收集（模块内存此时可读）�?
//
        KeStackAttachProcess(proc, &apcState);
        NTSTATUS st = STATUS_SUCCESS;
        PNPPV_ENTRY slot = nullptr;
        __try
        {
            PVOID first = reinterpret_cast<PVOID>(PAGE_ALIGN_DOWN(Va));            if (!MmIsAddressValid(first))
            {
                st = STATUS_INVALID_ADDRESS;
                __leave;
            }
            gpaLo = MmGetPhysicalAddress(first).QuadPart;
            PVOID second = reinterpret_cast<PVOID>(
                reinterpret_cast<ULONG_PTR>(first) + PAGE_SIZE);
            BOOLEAN secondValid = MmIsAddressValid(second);
            if (secondValid)
            {
                gpaHi = MmGetPhysicalAddress(second).QuadPart;
            }

            RtlCopyMemory(aligned, first, PAGE_SIZE);
            if (secondValid)
            {
                RtlCopyMemory(aligned + PAGE_SIZE, second, PAGE_SIZE);
            }
            else
            {
                RtlZeroMemory(aligned + PAGE_SIZE, PAGE_SIZE);
            }
            RtlCopyMemory(aligned + 0x2000, aligned, 0x2000);

            //
            // 登记槽位�?
//
            KeAcquireSpinLock(&g_PvLock, &oldIrql);
            for (ULONG i = 0; i < NPPV_MAX; i++)
            {
                if (!g_Pv[i].Active)
                {
                    slot = &g_Pv[i];
                    slot->Active = TRUE;
                    slot->VictimPid = VictimPid;
                    slot->VaLo = reinterpret_cast<ULONG_PTR>(first);
                    slot->GpaLo = gpaLo;
                    slot->GpaHi = secondValid ?
gpaHi : 0;
                    slot->OrigVa = first;
                    slot->Base = aligned;
                    slot->Raw = raw;
                    RtlZeroMemory(slot->ViewerPids,
                                  sizeof(slot->ViewerPids));
                    PvAddViewer(slot, WriterPid);
                    break;
                }
            }
            KeReleaseSpinLock(&g_PvLock, oldIrql);

            if (slot == nullptr)
            {
                st = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }
            pv = slot;
            createdHere = TRUE;

            //
            // 锁定页面防止换页漂移（仍在目标上下文内，PASSIVE）�?
// MDL 引用计数使物理帧不会被修剪或回收�?
//
            {
                PMDL mdl = IoAllocateMdl(first, PAGE_SIZE, FALSE, FALSE, nullptr);
                if (mdl != nullptr)
                {
                    NTSTATUS lockSt = STATUS_SUCCESS;
                    __try
                    {
                        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        lockSt = GetExceptionCode();
                    }
                    if (NT_SUCCESS(lockSt))
                    {
                        slot->PageMdl = mdl;
                    }
                    else
                    {
                        IoFreeMdl(mdl);
                        // 锁定失败不阻塞安装——降级为可漂移模�?
}
                }
            }

            //
            // 展开表：映像基址扫描 + .pdata 原样拷贝。失败仅降级精确展开�?
//
            imgBase = PvFindImageBaseAttached(first);
            if (imgBase != 0)
            {
                ULONG rvaLoTmp = 0;
                unwindCount = NpPvCollectUnwind(slot, imgBase, &rvaLoTmp);
                if (unwindCount != 0)
                {
                    slot->UnwindImageBase = imgBase;
                    slot->UnwindRvaLo =
                        static_cast<ULONG>(
                            reinterpret_cast<ULONG_PTR>(first) -
                            static_cast<ULONG_PTR>(imgBase));
                    unwindRvaLo = slot->UnwindRvaLo;
                    unwindOk = TRUE;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            st = STATUS_ACCESS_VIOLATION;
        }
        KeUnstackDetachProcess(&apcState);

        if (!NT_SUCCESS(st) || pv == nullptr)
        {
            InterlockedExchange(&g_PvCreating, 0);
            ExFreePoolWithTag(raw, 'VtPp');
            ObDereferenceObject(proc);
            return FALSE;
        }

        //
        // �?CPU 武装：两�?Present=0�?
//
        for (ULONG c = 0; c < NpHvGetProcessorCount(); c++)
        {
            PVIRTUAL_PROCESSOR_DATA vp = nullptr;
            if (NT_SUCCESS(NpHvGetProcessorData(c, &vp)) && vp != nullptr)
            {
                NpPvArmGroup(vp, pv);
            }
        }
        InterlockedExchange(&g_PvCreating, 0);
        NpHvLogPrint("[patch] view created pid=%lu va=0x%llx gpa=%llx/%llx "
                     "unwind=%s\n", VictimPid, Va, gpaLo, gpaHi,
                     unwindOk ? L"OK" : L"degraded");
    }
    else
    {
        PvAddViewer(pv, WriterPid);
    }

    ObDereferenceObject(proc);

    {
        PUCHAR clone = static_cast<PUCHAR>(pv->Base) + 0x2000;
        ULONG_PTR off = Va - reinterpret_cast<ULONG_PTR>(pv->OrigVa);
        RtlCopyMemory(clone + off, tmp, Length);
    }

    NpHvLogPrint("[patch] apply pid=%lu va=0x%llx len=%lu writer=%lu\n",
                 VictimPid, (PVOID)Va, Length, WriterPid);
    return TRUE;
}

// ---- 漂移校验（B3 防护�?-------------------------------------------------------

//
// 校验所有活动视图的目标页翻译是否仍指向登记帧�?
// 用户页被修剪出工作集再换入时物理帧可能改�?—�?一旦漂移，
// 残留武装会误伤复用帧的新主人，必须立即拆除视图�?
// PASSIVE_LEVEL 专用（内部附着目标进程）；由复位线程节流调用�?
//
VOID
NpPatchViewValidateAll(
    VOID
    )
{
    KIRQL oldIrql;
    PNPPV_ENTRY pv = nullptr;
    ULONG victimPid = 0;
    ULONG_PTR vaLo = 0, gpaLo = 0, gpaHi = 0;

    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    for (ULONG i = 0; i < NPPV_MAX; i++)
    {
        if (g_Pv[i].Active && g_Pv[i].VaLo != 0)
        {
            pv = &g_Pv[i];
            victimPid = pv->VictimPid;
            vaLo = pv->VaLo;
            gpaLo = pv->GpaLo;
            gpaHi = pv->GpaHi;
            break;
        }
    }
    KeReleaseSpinLock(&g_PvLock, oldIrql);

    if (pv == nullptr)
    {
        return;                                 // 无活动视�?
}

    PEPROCESS proc = nullptr;
    BOOLEAN ok = FALSE;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(
            ULongToHandle(victimPid), &proc)) || proc == nullptr)
    {
        //
        // 受害进程已不在：通知回调可能尚未轮到 —�?就地拆视图�?
//
        ok = FALSE;
    }
    else
    {
        KAPC_STATE apcState;
        KeStackAttachProcess(proc, &apcState);
        __try
        {
            PVOID first = reinterpret_cast<PVOID>(vaLo);
            PVOID second = reinterpret_cast<PVOID>(vaLo + PAGE_SIZE);
            BOOLEAN secondValid = MmIsAddressValid(second);

            if (!MmIsAddressValid(first))
            {
                ok = FALSE;                     // 页被换出且未�?—�?视图失效
                __leave;
            }
            ULONG64 curLo = MmGetPhysicalAddress(first).QuadPart;

            //
            // 帧一致性硬校验：低页帧必须完全一致；
            // 高页有效性状态必须一致；一致时高页帧也必须一致�?
// 内容级漂移由数据单步的分歧保留算法天然兜底�?
//
            ok = (curLo == gpaLo) &&
                 ((gpaHi != 0) == secondValid) &&
                 (!secondValid || gpaHi == 0 ||
                  static_cast<ULONG_PTR>(
                      MmGetPhysicalAddress(second).QuadPart) == gpaHi);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = FALSE;
        }
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(proc);
    }

    if (!ok)
    {
        NpHvLogPrint("[patch] drift detected pid=%lu "
                     "view dismantled "
                     "(re-apply patch to re-enable)\n", victimPid);
        NpPatchViewRemove(victimPid, vaLo);
    }
}

// ---- 卸载 / 移除 / 退�?---------------------------------------------------------

NTSTATUS
NpPatchViewRemove(
    ULONG VictimPid,
    ULONG_PTR Va
    )
{
    PNPPV_ENTRY pv = nullptr;
    KIRQL oldIrql;
    ULONG_PTR vaLo = PAGE_ALIGN_DOWN(Va);

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    for (ULONG i = 0; i < NPPV_MAX; i++)
    {
        if (g_Pv[i].Active && g_Pv[i].VictimPid == VictimPid &&
            g_Pv[i].VaLo == vaLo)
        {
            pv = &g_Pv[i];
            pv->Active = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PvLock, oldIrql);

    if (pv == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    for (ULONG c = 0; c < NpHvGetProcessorCount(); c++)
    {
        PVIRTUAL_PROCESSOR_DATA vp = nullptr;
        if (NT_SUCCESS(NpHvGetProcessorData(c, &vp)) && vp != nullptr)
        {
            NpHookRestoreIdentity(vp, pv->GpaLo);
            if (pv->GpaHi != 0)
            {
                NpHookRestoreIdentity(vp, pv->GpaHi);
            }
        }
    }

    KeAcquireSpinLock(&g_PvRetiredLock, &oldIrql);
    InsertTailList(&g_PvRetiredList, &pv->Retired);
    KeReleaseSpinLock(&g_PvRetiredLock, oldIrql);

    NpHvLogPrint("[patch] removed pid=%lu va=0x%llx\n", VictimPid, vaLo);
    return STATUS_SUCCESS;
}

VOID
NpPatchViewList(
    _Out_ PNPHV_PATCH_LIST_RESPONSE Resp
    )
{
    KIRQL oldIrql;
    ULONG count = 0;

    RtlZeroMemory(Resp, sizeof(*Resp));
    KeAcquireSpinLock(&g_PvLock, &oldIrql);
    for (ULONG i = 0; i < NPPV_MAX && count < 16; i++)
    {
        if (!g_Pv[i].Active || g_Pv[i].VaLo == 0)
        {
            continue;
        }
        Resp->Items[count].Va = reinterpret_cast<ULONG_PTR>(g_Pv[i].OrigVa);
        Resp->Items[count].VictimPid = g_Pv[i].VictimPid;
        Resp->Items[count].Length = 0;
        count++;
    }
    KeReleaseSpinLock(&g_PvLock, oldIrql);
    Resp->Count = count;
    Resp->Status = 0;
}

VOID
NpPatchViewUnloadBegin(
    VOID
    )
{
    KIRQL oldIrql;

    for (ULONG i = 0; i < NPPV_MAX; i++)
    {
        if (!g_Pv[i].Active)
        {
            continue;
        }

        for (ULONG c = 0; c < NpHvGetProcessorCount(); c++)
        {
            PVIRTUAL_PROCESSOR_DATA vp = nullptr;
            if (NT_SUCCESS(NpHvGetProcessorData(c, &vp)) && vp != nullptr)
            {
                NpHookRestoreIdentity(vp, g_Pv[i].GpaLo);
                if (g_Pv[i].GpaHi != 0)
                {
                    NpHookRestoreIdentity(vp, g_Pv[i].GpaHi);
                }
            }
        }

        KeAcquireSpinLock(&g_PvLock, &oldIrql);
        g_Pv[i].Active = FALSE;
        KeReleaseSpinLock(&g_PvLock, oldIrql);

        KeAcquireSpinLock(&g_PvRetiredLock, &oldIrql);
        InsertTailList(&g_PvRetiredList, &g_Pv[i].Retired);
        KeReleaseSpinLock(&g_PvRetiredLock, oldIrql);
    }

}

VOID
NpPatchViewFreeRetired(
    VOID
    )
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    for (;;)
    {
        KeAcquireSpinLock(&g_PvRetiredLock, &oldIrql);
        if (IsListEmpty(&g_PvRetiredList))
        {
            KeReleaseSpinLock(&g_PvRetiredLock, oldIrql);
            break;
        }
        entry = RemoveHeadList(&g_PvRetiredList);
        KeReleaseSpinLock(&g_PvRetiredLock, oldIrql);

        PNPPV_ENTRY pv = CONTAINING_RECORD(entry, NPPV_ENTRY, Retired);
        if (pv->Raw != nullptr)
        {
            ExFreePoolWithTag(pv->Raw, 'VtPp');
        }
        if (pv->PageMdl != nullptr)
        {
            MmUnlockPages(pv->PageMdl);
            IoFreeMdl(pv->PageMdl);
            pv->PageMdl = nullptr;
        }
    }
}

// ============================ 跳板构建 ============================
//
static
BOOLEAN
NpHookBuildTrampoline(
    _In_ PHOOK_INFO Hook
    )
{
    ULONG templateSize = TrampolineTemplateSize;
    ULONG bufferSize = templateSize + 16 + JUMPBACK_STUB_SIZE + 16;
    PUCHAR buffer;

    //
    // 可执行非分页内存（Guest 需要执行跳板代码，故必�?NPT 可见）�?
//
    buffer = static_cast<PUCHAR>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                                 bufferSize,
                                                 'kpoN'));
    if (buffer == nullptr)
    {
        return FALSE;
    }
    RtlZeroMemory(buffer, bufferSize);

    //
    // 复制模板并修补数据指针�?
//
    RtlCopyMemory(buffer, reinterpret_cast<PVOID>(&TrampolineTemplate), templateSize);

    *reinterpret_cast<ULONG_PTR*>(buffer + TRAMPOLINE_DATA_HOOKFUNC_OFF) =
        reinterpret_cast<ULONG_PTR>(Hook->Callback);
    *reinterpret_cast<ULONG_PTR*>(buffer + TRAMPOLINE_DATA_ORIGINAL_OFF) =
        Hook->OriginalAddress;
    *reinterpret_cast<ULONG_PTR*>(buffer + TRAMPOLINE_DATA_AFTERPROLOG_OFF) =
        Hook->OriginalAddress + Hook->PrologSize;

    //
    // 方案C：放行路径直接跳到【重定位后的克隆函数入口】—�?
// 序言（含�?cookie �?RIP 相对引用）在克隆上执行，由重定位�?
// 修正，不再复制序言到跳板。跳回桩已不需要�?
//
    *reinterpret_cast<ULONG_PTR*>(buffer + TRAMPOLINE_DATA_PROLOG_OFF) =
        reinterpret_cast<ULONG_PTR>(Hook->CloneVA) +
        NpRelocMapLookup(static_cast<const NP_RELOC_MAP*>(Hook->CloneMap), Hook->CloneMapCount, Hook->PageOffset);

    Hook->Trampoline = buffer;
    Hook->TrampolinePA = MmGetPhysicalAddress(buffer).QuadPart;
    return TRUE;
}

/*!
    @brief      �?
CPU 配置 Hook �?
NPT 叶子（状�?A：影子页0 + NX）�?
    @param[in]  Context - PHOOK_CPU_CONTEXT�? */
static
NTSTATUS
NpHookConfigureOnProcessor(
    _In_ PVOID Context
    )
{
    PHOOK_CPU_CONTEXT cpuContext = static_cast<PHOOK_CPU_CONTEXT>(Context);
    PHOOK_INFO hook = cpuContext->Hook;
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    NTSTATUS status;

    status = NpHvGetProcessorData(cpuContext->CpuIndex, &vpData);
    if (!NT_SUCCESS(status) || vpData == nullptr)
    {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 状�?A：GPA �?影子�?（干净拷贝），NX=1（取指陷阱）�?
// 内部会按需拆分 2MB 大页（从预分配池�?PT 页）�?
//
    NpHookSetLeaf(vpData,
                  hook->OriginalPhysical,
                  hook->ShadowPage0PA,
                  TRUE,
                  TRUE);
    return STATUS_SUCCESS;
}

/*!
    @brief      卸载路径：按 CPU 恢复 Hook 页的恒等映射�?
    @param[in]  Context - PHOOK_CPU_CONTEXT�? */
static
NTSTATUS
NpHookRestoreOnProcessor(
    _In_ PVOID Context
    )
{
    PHOOK_CPU_CONTEXT cpuContext = static_cast<PHOOK_CPU_CONTEXT>(Context);
    PHOOK_INFO hook = cpuContext->Hook;
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    NTSTATUS status;

    status = NpHvGetProcessorData(cpuContext->CpuIndex, &vpData);
    if (!NT_SUCCESS(status) || vpData == nullptr)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NpHookRestoreIdentity(vpData, hook->OriginalPhysical);
    return STATUS_SUCCESS;
}

/*!
    @brief      在全部处理器上执行回调（逐个绑定亲和性）�?
    @param[in]  Callback - 回调�?    @param[in]  Context  - 回调参数（PHOOK_CPU_CONTEXT，CpuIndex 会被更新）�?
    @return     STATUS_SUCCESS 或错误码�? */
static
NTSTATUS
NpHookExecuteOnEachProcessor(
    _In_ NTSTATUS(*Callback)(PVOID),
    _In_ PVOID Context
    )
{
    NTSTATUS status;
    ULONG numProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;

    status = STATUS_SUCCESS;
    numProcessors = NpHvGetProcessorCount();

    for (ULONG i = 0; i < numProcessors; i++)
    {
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        //
        // 告诉回调当前 CPU 的全局索引�?
//
        static_cast<PHOOK_CPU_CONTEXT>(Context)->CpuIndex = i;

        status = Callback(Context);

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
        {
            break;
        }
    }
    return status;
}

/*!
    @brief      从模�?.pdata 构建�?8KB 克隆块重叠的代码区间�?
    @details    区间坐标为块内偏�?[Beg, End)，升序且已合并�?                起点位于本块之前（BeginAddress < PageRvaLo）的条目—�?                前一函数跨页流入本块的尾部——被排除：其代码在本块内
                从非指令边界开始，克隆无法正确重定位；该区域由 NPF
                处理器以"恒等+单步"从真页执行�?                .pdata 之外（跳转表/对齐/填充）视为数据，重定位器
                只处理区间内字节�?
    @return     区间数；0 = 无（调用方应拒绝安装）�? */
static
ULONG
NpRelocBuildCodeRanges(
    _In_ PVOID ImageBase,
    _In_ ULONG PageRvaLo,
    _Out_writes_(MaxRanges) NP_RELOC_RANGE* Ranges,
    _In_ ULONG MaxRanges)
{
    ULONG count = 0;

    if (ImageBase == nullptr || Ranges == nullptr || MaxRanges == 0)
    {
        return 0;
    }

    __try
    {
        IMAGE_DOS_HEADER* dos = static_cast<IMAGE_DOS_HEADER*>(ImageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }
        PIMAGE_NT_HEADERS nth = RtlImageNtHeader(ImageBase);
        if (nth == nullptr)
        {
            return 0;
        }
        IMAGE_DATA_DIRECTORY* dir =
            &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (dir->Size < sizeof(RUNTIME_FUNCTION))
        {
            return 0;
        }

        PRUNTIME_FUNCTION pf = reinterpret_cast<PRUNTIME_FUNCTION>(
            reinterpret_cast<PUCHAR>(ImageBase) + dir->VirtualAddress);
        ULONG n = dir->Size / sizeof(RUNTIME_FUNCTION);
        ULONG lo = PageRvaLo;
        ULONG hi = PageRvaLo + NP_RELOC_BLOCK_SIZE;

        for (ULONG i = 0; i < n && count < MaxRanges; i++)
        {
            if (pf[i].BeginAddress < lo)
            {
                //
                // 跨页条目（函数起始于上一页）：本块内是其尾部�?
// 指令边界未知，无法重定位 �?排除（NPF 恒等单步兜底）�?
//
                continue;
            }
            if (pf[i].EndAddress <= lo || pf[i].BeginAddress >= hi)
            {
                continue;
            }
            ULONG b = pf[i].BeginAddress - lo;
            ULONG e = (pf[i].EndAddress < hi) ?
pf[i].EndAddress - lo
                                              : NP_RELOC_BLOCK_SIZE;
            if (e <= b)
            {
                continue;
            }
            if (count > 0 && Ranges[count - 1].End >= b)
            {
                if (Ranges[count - 1].End < e)
                {
                    Ranges[count - 1].End = e;
                }
            }
            else
            {
                Ranges[count].Beg = b;
                Ranges[count].End = e;
                count++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
    return count;
}

/*!
    @brief      安装一�?
NPT 无痕 Hook�?
    @param[in]  OriginalAddress - �?
Hook 函数入口地址（内核态）�?    @param[in]  Callback        - 回调（见 HOOK_CALLBACK）�?    @param[out] HookInfo        - 返回 Hook 句柄（用于卸载）�?
    @return     STATUS_SUCCESS 或错误码�? */
_Use_decl_annotations_
NTSTATUS
NpHookInstallHook(
    ULONG_PTR OriginalAddress,
    HOOK_CALLBACK Callback,
    PHOOK_INFO* HookInfo)
{
    PHOOK_INFO hook;
    NTSTATUS status;
    PUCHAR originalPageVa;
    ULONG_PTR originalPhysical;
    KIRQL oldIrql;

    if (HookInfo == nullptr || Callback == nullptr || OriginalAddress == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *HookInfo = nullptr;

    //
    // 仅支持内核态地址（系统空间）�?
//
    if (OriginalAddress < 0xFFFF800000000000ULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 解码序言长度（至�?NPTHOOK_MIN_PROLOG_SIZE 字节、指令边界对齐）�?
//
    UINT8 codeBytes[16];
    RtlCopyMemory(codeBytes, reinterpret_cast<PVOID>(OriginalAddress),
                  sizeof(codeBytes));

    UINT32 prologSize = 0;
    if (NptHook::GetPrologueLength(codeBytes,
                                   NPTHOOK_MIN_PROLOG_SIZE,
                                   &prologSize) == false)
    {
        NpHvLogPrint("NpHookInstallHook: 无法解码函数 0x%p 的序言\n",
                     reinterpret_cast<PVOID>(OriginalAddress));
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 计算页物理地址，并检查该页是否已�?Hook�?
//
    originalPhysical = MmGetPhysicalAddress(
                           reinterpret_cast<PVOID>(PAGE_ALIGN_DOWN(OriginalAddress))).QuadPart;
    if (originalPhysical == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    BOOLEAN alreadyHooked = (NpHookFindHookByPage(originalPhysical) != nullptr);
    KeReleaseSpinLock(&g_HookListLock, oldIrql);
    if (alreadyHooked)
    {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // 分配 Hook 结构�?
//
    hook = static_cast<PHOOK_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                   sizeof(HOOK_INFO),
                                                   'kpoN'));
    if (hook == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(hook, sizeof(HOOK_INFO));

    hook->OriginalAddress = OriginalAddress;
    hook->OriginalPhysical = originalPhysical;
    hook->PageOffset = static_cast<ULONG>(PAGE_OFFSET(OriginalAddress));
    hook->Callback = Callback;
    hook->PrologSize = static_cast<UINT8>(prologSize);
    RtlCopyMemory(hook->OriginalCode, codeBytes, prologSize);

    //
    // 分配影子页并拷贝原始页内容�?
//
    originalPageVa = reinterpret_cast<PUCHAR>(PAGE_ALIGN_DOWN(OriginalAddress));
    hook->ShadowPage0 = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'kpoN');
    hook->ShadowPage1 = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'kpoN');
    if (hook->ShadowPage0 == nullptr || hook->ShadowPage1 == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlCopyMemory(hook->ShadowPage0, originalPageVa, PAGE_SIZE);
    RtlCopyMemory(hook->ShadowPage1, originalPageVa, PAGE_SIZE);
    static_cast<PUCHAR>(hook->ShadowPage1)[hook->PageOffset] = 0xCC;  // INT3

    hook->ShadowPage0PA = MmGetPhysicalAddress(hook->ShadowPage0).QuadPart;
    hook->ShadowPage1PA = MmGetPhysicalAddress(hook->ShadowPage1).QuadPart;

    //
    // 方案C：克隆页重定位（双页镜像 [P][P+0x1000]）�?
// 1) 源块 = 原页 + 镜像页的字节拷贝（临时缓冲）�?
// 2) 解析模块基址与代码区间（.pdata：块内全部函数的范围）；
    // 3) NpReloc 把代码区间内的相对跳�?/ RIP 相对引用改写为绝对寻址�?
//    区间外（跳转�?对齐/填充）原样保留；
    // 4) 输出到可执行克隆块（EXECUTE 池，常驻可执行）�?
//
    {
        PUCHAR srcBlock = static_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, NP_RELOC_BLOCK_SIZE, 'kpoN'));
        if (srcBlock == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        RtlCopyMemory(srcBlock, originalPageVa, PAGE_SIZE);

        //
        // 镜像下一页（P+0x1000）：跨页函数体的续接执行区�?
// 下一页可能未映射（函数恰在页尾结束）�?清零占位�?
//
        PUCHAR nextPageVa = originalPageVa + PAGE_SIZE;
        __try
        {
            if (MmIsAddressValid(nextPageVa))
            {
                RtlCopyMemory(srcBlock + PAGE_SIZE, nextPageVa, PAGE_SIZE);
            }
            else
            {
                RtlZeroMemory(srcBlock + PAGE_SIZE, PAGE_SIZE);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            RtlZeroMemory(srcBlock + PAGE_SIZE, PAGE_SIZE);
        }

        //
        // 模块基址：经 RtlLookupFunctionEntry 导出入口查询�?
// 函数无展开条目（无 .pdata）→ 无法构建代码区间 �?拒绝安装�?
//
        ULONG64 imgBase2 = 0;
        typedef PRUNTIME_FUNCTION(*PFN_LFE2)(ULONG64, PULONG64, PVOID);
        UNICODE_STRING nLfe2;
        RtlInitUnicodeString(&nLfe2, L"RtlLookupFunctionEntry");
        PFN_LFE2 lfe2 = (PFN_LFE2)MmGetSystemRoutineAddress(&nLfe2);
        PRUNTIME_FUNCTION selfRf2 = nullptr;
        if (lfe2 != nullptr)
        {
            selfRf2 = lfe2(OriginalAddress, &imgBase2, nullptr);
        }
        if (selfRf2 == nullptr || imgBase2 == 0)
        {
            ExFreePoolWithTag(srcBlock, 'kpoN');
            NpHvLogPrint("NpHookInstallHook: 0x%p �?.pdata 条目，拒绝克隆\n",
                         reinterpret_cast<PVOID>(OriginalAddress));
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        ULONG pageRvaLo2 = static_cast<ULONG>(
            reinterpret_cast<PUCHAR>(originalPageVa) -
            reinterpret_cast<PUCHAR>(imgBase2));
        NP_RELOC_RANGE ranges[64];
        ULONG rangeCount = NpRelocBuildCodeRanges(
            reinterpret_cast<PVOID>(imgBase2), pageRvaLo2, ranges, 64);
        if (rangeCount == 0)
        {
            ExFreePoolWithTag(srcBlock, 'kpoN');
            NpHvLogPrint("NpHookInstallHook: 0x%p 无代码区间，拒绝克隆\n",
                         reinterpret_cast<PVOID>(OriginalAddress));
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        //
        // 克隆块：EXECUTE 池，5 �?+ 1 页对齐余量�?
//   [CloneVA .. +0x4000) 重定位代�?
//   [CloneVA + 0x4000 .. +0x5000) 展开 INFO blob
        //
        PUCHAR cloneRaw = static_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                            PAGE_SIZE * 5 + PAGE_SIZE, 'kpoN'));
        if (cloneRaw == nullptr)
        {
            ExFreePoolWithTag(srcBlock, 'kpoN');
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        PUCHAR cloneAligned = reinterpret_cast<PUCHAR>(
            (reinterpret_cast<ULONG_PTR>(cloneRaw) + PAGE_SIZE - 1) &
            ~(static_cast<ULONG_PTR>(PAGE_SIZE) - 1));

        NP_RELOC_MAP* map = static_cast<NP_RELOC_MAP*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED,
                            NP_RELOC_MAX_ENTRIES * sizeof(NP_RELOC_MAP),
                            'kpoN'));
        if (map == nullptr)
        {
            ExFreePoolWithTag(srcBlock, 'kpoN');
            ExFreePoolWithTag(cloneRaw, 'kpoN');
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        NP_RELOC_RESULT rr;
        rr.Map = map;
        rr.MapCapacity = NP_RELOC_MAX_ENTRIES;
        rr.OutLen = 0;
        rr.MapCount = 0;
        if (!NpRelocRelocateBlock(srcBlock,
                                  reinterpret_cast<ULONG_PTR>(originalPageVa),
                                  hook->PageOffset,
                                  ranges, rangeCount,
                                  cloneAligned, NP_RELOC_MAX_OUT, &rr))
        {
            ExFreePoolWithTag(srcBlock, 'kpoN');
            ExFreePoolWithTag(cloneRaw, 'kpoN');
            ExFreePoolWithTag(map, 'kpoN');
            NpHvLogPrint("NpHookInstallHook: 0x%p 克隆重定位失败，拒绝安装\n",
                         reinterpret_cast<PVOID>(OriginalAddress));
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }
        ExFreePoolWithTag(srcBlock, 'kpoN');

        hook->CloneRaw = cloneRaw;
        hook->CloneVA = cloneAligned;
        hook->CloneMap = map;
        hook->CloneMapCount = rr.MapCount;
        hook->CloneCodeLen = rr.OutLen;
        hook->CloneTailEnd = (rangeCount > 0) ?
ranges[0].Beg : hook->PageOffset;
        NpHvLogPrint("NpHookInstallHook: clone 0x%p (len=0x%x, map=%lu, "
                     "tail=0x%x) relocated ok\n",
                     cloneAligned, rr.OutLen, rr.MapCount, hook->CloneTailEnd);
    }

    //
    // 生成跳板（含序言副本与跳回桩）�?
//
    if (NpHookBuildTrampoline(hook) == FALSE)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // 先入链表（让 VMEXIT 处理器可查到�?Hook），
    // 再在全部 CPU 上配置状�?A。期间若发生取指 NPF，处理器�?
// 按需拆分大页（原子操作），与安装路径无冲突�?
//
    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    InsertTailList(&g_HookListHead, &hook->ListEntry);
    hook->Active = TRUE;
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    HOOK_CPU_CONTEXT cpuContext;
    cpuContext.Hook = hook;
    cpuContext.CpuIndex = 0;

    status = NpHookExecuteOnEachProcessor(NpHookConfigureOnProcessor, &cpuContext);
    if (!NT_SUCCESS(status))
    {
        //
        // 配置失败：回滚。部�?CPU �?NPT 可能已指向影子页（TLB 有缓存）�?
// 立即释放�?use-after-free —�?延迟释放，等卸载时统一清理�?
//
        NpHookUninstallHook(hook, FALSE);
        return status;
    }

    //
    // 方案C 展开表：为克隆页构建精确展开信息，并惰性安�?
// RtlLookupFunctionEntry 元钩子。失败仅降级为不精确展开�?
//
    {
        ULONG64 imgBase = 0;
        typedef PRUNTIME_FUNCTION(*PFN_LFE)(ULONG64, PULONG64, PVOID);
        PFN_LFE lfe;
        UNICODE_STRING n;

        RtlInitUnicodeString(&n, L"RtlLookupFunctionEntry");
        lfe = (PFN_LFE)MmGetSystemRoutineAddress(&n);
        if (lfe != nullptr && hook->CloneVA != nullptr)
        {
            if (lfe(OriginalAddress, &imgBase, nullptr) != nullptr &&
                NpHookBuildCloneUnwind(hook, originalPageVa, imgBase) > 0)
            {
                InterlockedIncrement(&g_CloneActiveCount);
                NpHookEnsureUnwindMaster();

                //
                // 元钩子自检：经导出入口查询克隆区间，必须命中我们的条目�?
// 若失败说明该构建上导出符号与实现体分离等异常情况�?
// 精确展开自动降级（不影响稳定性）�?
//
                ULONG64 selfBase = 0;
                PRUNTIME_FUNCTION selfRf = lfe(
                    reinterpret_cast<ULONG64>(hook->CloneVA), &selfBase, nullptr);
                if (selfRf != nullptr &&
                    selfBase == reinterpret_cast<ULONG_PTR>(hook->CloneVA))
                {
                    NpHvLogPrint("[hook] unwind selftest OK (%u entries)\n",
                                 hook->CloneUnwindCount);
                }
                else
                {
                    NpHvLogPrint("[hook] unwind selftest FAIL —�?"
                                 "本构建元钩子不可达，精确展开降级\n");
                }
            }
        }
    }

    *HookInfo = hook;
    NpHvLogPrint("NpHookInstallHook: 0x%p (pa=0x%llx, prolog=%u, tramp=0x%p)\n",
                 reinterpret_cast<PVOID>(OriginalAddress),
                 originalPhysical,
                 prologSize,
                 hook->Trampoline);
    return STATUS_SUCCESS;

Exit:
    if (hook->ShadowPage0 != nullptr)
    {
        ExFreePoolWithTag(hook->ShadowPage0, 'kpoN');
    }
    if (hook->ShadowPage1 != nullptr)
    {
        ExFreePoolWithTag(hook->ShadowPage1, 'kpoN');
    }
    if (hook->CloneRaw != nullptr)
    {
        ExFreePoolWithTag(hook->CloneRaw, 'kpoN');
    }
    if (hook->CloneMap != nullptr)
    {
        ExFreePoolWithTag(hook->CloneMap, 'kpoN');
    }
    if (hook->Trampoline != nullptr)
    {
        ExFreePoolWithTag(hook->Trampoline, 'kpoN');
    }
    ExFreePoolWithTag(hook, 'kpoN');
    return status;
}

/*!
    @brief      释放单个 Hook 的资源（影子页、跳板、结构体）�?
    @param[in]  HookInfo - 已从活动链表摘除�?
Hook�? */
static
VOID
NpHookFreeHookInfo(
    _In_ PHOOK_INFO HookInfo
    )
{
    if (HookInfo->Trampoline != nullptr)
    {
        ExFreePoolWithTag(HookInfo->Trampoline, 'kpoN');
    }
    if (HookInfo->ShadowPage0 != nullptr)
    {
        ExFreePoolWithTag(HookInfo->ShadowPage0, 'kpoN');
    }
    if (HookInfo->ShadowPage1 != nullptr)
    {
        ExFreePoolWithTag(HookInfo->ShadowPage1, 'kpoN');
    }
    if (HookInfo->CloneUnwind != nullptr)
    {
        if (HookInfo->CloneUnwindCount != 0)
        {
            InterlockedDecrement(&g_CloneActiveCount);
        }
        ExFreePoolWithTag(HookInfo->CloneUnwind, 'kpoN');
        HookInfo->CloneUnwindCount = 0;
    }
    if (HookInfo->CloneMap != nullptr)
    {
        ExFreePoolWithTag(HookInfo->CloneMap, 'kpoN');
        HookInfo->CloneMap = nullptr;
        HookInfo->CloneMapCount = 0;
    }
    if (HookInfo->CloneRaw != nullptr)
    {
        ExFreePoolWithTag(HookInfo->CloneRaw, 'kpoN');
    }
    ExFreePoolWithTag(HookInfo, 'kpoN');
}

/*!
    @brief      卸载一�?
NPT Hook�?
    @param[in]  HookInfo      - NpHookInstallHook 返回的句柄�?    @param[in]  FreeResources - TRUE  立即释放资源（仅在确认无线程正在
                                      执行�?
Hook 路径时使用）�?
FALSE 挂入退休链表，�?
NpHookFreeRetiredHooks
                                      在去虚拟化完成后统一释放（推荐）�?
    @return     STATUS_SUCCESS�? */
_Use_decl_annotations_
NTSTATUS
NpHookUninstallHook(
    PHOOK_INFO HookInfo,
    BOOLEAN FreeResources)
{
    KIRQL oldIrql;

    if (HookInfo == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 先从链表摘除（不再接受新�?NPF 匹配）�?
//
    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    HookInfo->Active = FALSE;
    RemoveEntryList(&HookInfo->ListEntry);
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    //
    // 在所�?CPU 上恢复恒等映射�?
//
    HOOK_CPU_CONTEXT cpuContext;
    cpuContext.Hook = HookInfo;
    cpuContext.CpuIndex = 0;
    NpHookExecuteOnEachProcessor(NpHookRestoreOnProcessor, &cpuContext);

    if (FreeResources != FALSE)
    {
        //
        // 立即释放。调用方必须保证没有其他 CPU 正在执行
        // 跳板/影子页路径（否则 use-after-free）�?
//
        NpHookFreeHookInfo(HookInfo);
    }
    else
    {
        //
        // 延迟释放：挂入退休链表，等待驱动卸载完成、虚拟化关闭后再释放�?
//
        KeAcquireSpinLock(&g_RetiredListLock, &oldIrql);
        InsertTailList(&g_RetiredHookList, &HookInfo->ListEntry);
        KeReleaseSpinLock(&g_RetiredListLock, oldIrql);
    }

    NpHvLogPrint("NpHookUninstallHook: done (FreeResources=%u)\n",
                 FreeResources ? 1 : 0);
    return STATUS_SUCCESS;
}

/*!
    @brief      卸载全部 Hook（驱动卸载时调用）�?
    @param[in]  FreeResources - 同上。驱动卸载路径必须传 FALSE�?                                �?
NpHookFreeRetiredHooks 延迟释放�?
    @return     STATUS_SUCCESS�? */
_Use_decl_annotations_
NTSTATUS
NpHookUninstallAllHooks(
    BOOLEAN FreeResources)
{
    KIRQL oldIrql;

    for (;;)
    {
        PHOOK_INFO hook = nullptr;

        KeAcquireSpinLock(&g_HookListLock, &oldIrql);
        if (IsListEmpty(&g_HookListHead))
        {
            KeReleaseSpinLock(&g_HookListLock, oldIrql);
            break;
        }
        hook = CONTAINING_RECORD(g_HookListHead.Flink, HOOK_INFO, ListEntry);
        RemoveEntryList(&hook->ListEntry);
        hook->Active = FALSE;
        KeReleaseSpinLock(&g_HookListLock, oldIrql);

        //
        // 恢复恒等映射�?
//
        HOOK_CPU_CONTEXT cpuContext;
        cpuContext.Hook = hook;
        cpuContext.CpuIndex = 0;
        NpHookExecuteOnEachProcessor(NpHookRestoreOnProcessor, &cpuContext);

        if (FreeResources != FALSE)
        {
            NpHookFreeHookInfo(hook);
        }
        else
        {
            KeAcquireSpinLock(&g_RetiredListLock, &oldIrql);
            InsertTailList(&g_RetiredHookList, &hook->ListEntry);
            KeReleaseSpinLock(&g_RetiredListLock, oldIrql);
        }
    }
    return STATUS_SUCCESS;
}

/*!
    @brief      释放所有退�?
Hook 的资源�?
    @details    必须在虚拟化已关闭、且所有线程均已离开跳板/影子页之�?                调用（即驱动卸载流程的最后阶段）。此时释放绝对安全：
                NPT 不再参与地址翻译，跳�?影子页也无任何执行者�?
    @return     STATUS_SUCCESS�? */
_Use_decl_annotations_
NTSTATUS
NpHookFreeRetiredHooks(
    VOID)
{
    KIRQL oldIrql;

    for (;;)
    {
        PHOOK_INFO hook = nullptr;

        KeAcquireSpinLock(&g_RetiredListLock, &oldIrql);
        if (IsListEmpty(&g_RetiredHookList))
        {
            KeReleaseSpinLock(&g_RetiredListLock, oldIrql);
            break;
        }
        hook = CONTAINING_RECORD(g_RetiredHookList.Flink, HOOK_INFO, ListEntry);
        RemoveEntryList(&hook->ListEntry);
        KeReleaseSpinLock(&g_RetiredListLock, oldIrql);

        NpHookFreeHookInfo(hook);
    }
    return STATUS_SUCCESS;
}

/*!
    @brief      NPF（嵌套页错误）处理。由 VMEXIT 分发器调用�?
    @details    只处理取指违例（方案C 状态机）：
      - 命中 Hook �?
RIP==入口：状�?A �?B（映射影子页1，NX=0，入�?
INT3�?      - 命中 Hook �?
RIP!=入口：重定向到克隆页同偏移（叶子保持 A 态，
        不存�?C �?—�?方案C 的核心：真页永不解除武装�?      - 未命�?
Hook：返�?
FALSE（分发器做恒等自愈）

    @param[in]  VpData   - �?
CPU 数据�?    @param[in]  FaultGpa - 故障 GPA�?    @param[in]  FaultRip - 故障 RIP（取指地址）�?    @param[in]  ErrorCode - NPF 错误码�?
    @return     TRUE 已处理；FALSE 未命�?
Hook�? */
_Use_decl_annotations_
BOOLEAN
NpHookHandleNpf(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR FaultGpa,
    ULONG_PTR FaultRip,
    ULONG ErrorCode)
{
    PHOOK_INFO hook;
    KIRQL oldIrql;

    //
    // 只处理取指违例�?
//
    if ((ErrorCode & NPF_ERROR_IFETCH) == 0)
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    hook = NpHookFindHookByPage(FaultGpa);
    if (hook != nullptr)
    {
        if (FaultRip == hook->OriginalAddress)
        {
            //
            // 入口取指：状�?A �?B。影子页1 入口�?INT3�?
//
            NpHookSetLeaf(VpData,
                          hook->OriginalPhysical,
                          hook->ShadowPage1PA,
                          FALSE,          // NX=0，可执行
                          TRUE);
        }
        else
        {
            ULONG pageOff = static_cast<ULONG>(FaultRip & 0xFFF);
            if (pageOff < hook->CloneTailEnd)
            {
                //
                // 块首非重定位区域（前一函数跨页流入的尾�?/ 填充）：
                // 克隆里只有未对齐的逐字节拷贝，无法安全执行。改�?
// 恒等 + TF 单步，从真页执行这一条指令（语义正确�?
// 相对寻址全部命中原地址），#DB 收口时立即重武装�?
// 窗口 = 单条指令；该区域不是 hook 目标函数本身�?
// 确定性拦截不受影响�?
//
                NpHookRestoreIdentity(VpData, FaultGpa & ~static_cast<ULONG_PTR>(0xFFF));
                VpData->GuestVmcb.StateSaveArea.Rflags |= NPHOOK_RFLAGS_TF;
                g_DataStepHook[VpData->CpuIndex] = hook;
                g_DataStepIsWrite[VpData->CpuIndex] = FALSE;
            }
            else
            {
                //
                // 页内取指（跳板跳�?/ 同页邻居函数 / 自愈）：重定向到
                // 克隆页同偏移（经重定位映射表换算）。方案C 下不存在
                // C 态——真页叶子永远保�?A 态（NX），任何取指要么命中
                // 入口陷阱、要么落到克隆，不存在第三种可能，因此没�?
// 暴露窗口�?
//
                VpData->GuestVmcb.StateSaveArea.Rip =
                    reinterpret_cast<ULONG_PTR>(hook->CloneVA) +
                    NpRelocMapLookup(static_cast<const NP_RELOC_MAP*>(hook->CloneMap), hook->CloneMapCount,
                                     pageOff);
            }
        }
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    return (hook != nullptr);
}

/*!
    @brief      #BP（INT3）处理。由 VMEXIT 分发器调用�?
    @details    命中 Hook：把 Guest RIP 重定向到跳板，并立即�?
NPT
                复位到状�?A（影子页0 + NX=1），将影子页1 的暴�?                窗口压缩到单�?
INT3�?
    @param[in]  VpData - �?
CPU 数据�?
    @return     TRUE 已处理（RIP 已重定向）；FALSE 非本框架�?
INT3�? */
_Use_decl_annotations_
BOOLEAN
NpHookHandleBreakpoint(
    PVIRTUAL_PROCESSOR_DATA VpData)
{
    PHOOK_INFO hook;
    ULONG_PTR rip = VpData->GuestVmcb.StateSaveArea.Rip;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    hook = NpHookFindHookByAddress(rip);
    if (hook != nullptr)
    {
        //
        // 重定向到跳板�?
//
        VpData->GuestVmcb.StateSaveArea.Rip =
            reinterpret_cast<ULONG_PTR>(hook->Trampoline);

        //
        // 立即复位到状�?A（影子页0 + NX=1），为下次触发做准备�?
//
        NpHookSetLeaf(VpData,
                      hook->OriginalPhysical,
                      hook->ShadowPage0PA,
                      TRUE,
                      TRUE);
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    return (hook != nullptr);
}

/*!
    @brief      复位全部影子页到状�?A（vmmcall 处理）�?
    @param[in]  VpData - �?
CPU 数据�?
    @return     TRUE�? */
_Use_decl_annotations_
BOOLEAN
NpHookResetAllShadows(
    PVIRTUAL_PROCESSOR_DATA VpData)
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    for (entry = g_HookListHead.Flink;
         entry != &g_HookListHead;
         entry = entry->Flink)
    {
        PHOOK_INFO hook = CONTAINING_RECORD(entry, HOOK_INFO, ListEntry);
        NpHookSetLeaf(VpData,
                      hook->OriginalPhysical,
                      hook->ShadowPage0PA,
                      TRUE,
                      TRUE);
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    return TRUE;
}

/*!
    @brief      把指�?
GPA 的叶子恢复为恒等映射（未知取指违例自愈）�?
    @param[in]  VpData - �?
CPU 数据�?    @param[in]  Gpa    - 客机物理地址�? */
_Use_decl_annotations_
VOID
NpHookRestoreIdentity(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR Gpa)
{
    NpHookSetLeaf(VpData, Gpa, Gpa, FALSE, TRUE);
    NpHookTryMergeLargePage(VpData, Gpa);
}

/*!
    @brief      尝试把已恢复恒等�?4KB 拆分页合并回 2MB 大页�?
    @details    PT 页池每核�?64 页；�?
Hook/断点卸载只恢复叶子而不
                回写大页 PDE，每个拆分的不同 2MB 区域永久占用一页，
                64 个区域后池耗尽 �?�?
Hook 装不上。本函数检查目�?
PT 页全�?512 项是否都是标准恒等叶子（Present +
                PFN==大页�?
idx + P/RW/US + 非大页项），全部满足�?                原子回写 PDE 为大页并释放 PT 页�?
    @note       可在 VMEXIT（高 IRQL）路径调用：仅遍历读 + 原子 CAS�?                不分配不等待。若 CAS 失败（并发有新的拆分/hook），
                保留 PT 页（位图不清），下次再试�? */
_Use_decl_annotations_
VOID
NpHookTryMergeLargePage(
    PVIRTUAL_PROCESSOR_DATA VpData,
    ULONG_PTR Gpa)
{
    PNPT_ROOT root = VpData->NptRoot;
    ULONG pdptIndex = static_cast<ULONG>((Gpa >> 30) & 0x1FF);
    ULONG pdIndex = static_cast<ULONG>((Gpa >> 21) & 0x1FF);
    ULONG_PTR largeBase = Gpa & ~static_cast<ULONG_PTR>(2 * 1024 * 1024 - 1);
    PNPT_ENTRY pde;
    PNPT_ENTRY pt = nullptr;
    ULONG_PTR ptPa = 0;
    ULONG ptSlot = NPTHOOK_MAX_SPLIT_PT_PER_CPU;

    if (!root->Pml4[0].Fields.Present ||
        !root->Pdpt[pdptIndex].Fields.Present)
    {
        return;
    }
    pde = &root->Pd[pdptIndex][pdIndex];
    if (pde->Fields.Present == 0 || pde->Fields.PatOrPs != 0)
    {
        return;                         // 页不存在或仍是大页（无需合并�?
}

    ptPa = pde->Fields.PageFrameNumber << 12;
    for (ULONG k = 0; k < NPTHOOK_MAX_SPLIT_PT_PER_CPU; k++)
    {
        if (root->PtPhysical[k] == ptPa)
        {
            pt = root->Pt[k];
            ptSlot = k;
            break;
        }
    }
    if (pt == nullptr)
    {
        return;                         // 不在池中（非本框架拆分），不�?
}

    //
    // 检�?512 项全部为恒等叶子：Present、PFN==大页�?idx、P/RW/US�?
// 非大页项、无 NX。任一不满足（�?hook/断点残留）则放弃�?
//
    for (ULONG i = 0; i < 512; i++)
    {
        NPT_ENTRY e;
        e.AsUInt64 = pt[i].AsUInt64;
        if (!e.Fields.Present || e.Fields.PatOrPs)
        {
            return;
        }
        if ((e.Fields.PageFrameNumber << 12) != largeBase + i * PAGE_SIZE)
        {
            return;
        }
        if (!e.Fields.Write || !e.Fields.User || e.Fields.NoExecute)
        {
            return;
        }
    }

    //
    // 全部恒等：原子回写大�?PDE�?
//
    NPT_ENTRY newPde;
    newPde.AsUInt64 = 0;
    newPde.Fields.Present = 1;
    newPde.Fields.Write = 1;
    newPde.Fields.User = 1;
    newPde.Fields.Accessed = 1;
    newPde.Fields.PageFrameNumber = largeBase >> 12;
    newPde.Fields.PatOrPs = 1;              // 2MB 大页

    NPT_ENTRY oldValue;
    oldValue.AsUInt64 = InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(pde),
        newPde.AsUInt64,
        pde->AsUInt64);
    if (oldValue.AsUInt64 != pde->AsUInt64)
    {
        return;                             // 并发修改，保留 PT 页
    }

    //
    // 回写成功：释�?PT 页回池�?
//
    NpHookReleasePtPage(root, ptPa);
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;
    (void)ptSlot;
}

/*!
    @brief      电源恢复后重新应用全�?
Hook（NPT 在睡眠期间被清空重建）�?
    @return     STATUS_SUCCESS�? */
_Use_decl_annotations_
NTSTATUS
NpHookReapplyAllHooks(
    VOID)
{
    PHOOK_INFO hooks[64];
    ULONG count = 0;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    //
    // 快照列表（避免在持有自旋锁时做亲和性切换）�?
//
    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    for (entry = g_HookListHead.Flink;
         entry != &g_HookListHead && count < ARRAYSIZE(hooks);
         entry = entry->Flink)
    {
        hooks[count++] = CONTAINING_RECORD(entry, HOOK_INFO, ListEntry);
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);

    for (ULONG i = 0; i < count; i++)
    {
        HOOK_CPU_CONTEXT cpuContext;
        cpuContext.Hook = hooks[i];
        cpuContext.CpuIndex = 0;
        NpHookExecuteOnEachProcessor(NpHookConfigureOnProcessor, &cpuContext);
    }
    return STATUS_SUCCESS;
}

/*!
    @brief      Hook 管理器初始化�? */
VOID
NpHookManagerInitialize(
    VOID
    )
{
    InitializeListHead(&g_HookListHead);
    KeInitializeSpinLock(&g_HookListLock);
    InitializeListHead(&g_RetiredHookList);
    KeInitializeSpinLock(&g_RetiredListLock);

    InitializeListHead(&g_PvRetiredList);
    KeInitializeSpinLock(&g_PvRetiredLock);

    //
    // 方案C：注册数据单步的 #DB 收口。先于断点服务注册（hookmgr �?
// DriverEntry 虚拟化前阶段初始化），但只在自身挂起标志置位时消费，
    // 与断点单步互不干扰�?
//
    NpHvRegisterVmExitHandler(VMEXIT_EXCEPTION_DB, NPHOOK_VMEXIT_HANDLER_COMPAT);
}

/*!
    @brief      统计当前活动 Hook 数量（R3 状态查询用）�? */
_Use_decl_annotations_
ULONG
NpHookGetActiveCount(
    VOID)
{
    PLIST_ENTRY entry;
    ULONG count;
    KIRQL oldIrql;

    count = 0;
    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    for (entry = g_HookListHead.Flink;
         entry != &g_HookListHead;
         entry = entry->Flink)
    {
        PHOOK_INFO hook = CONTAINING_RECORD(entry, HOOK_INFO, ListEntry);
        if (hook->Active)
        {
            count++;
        }
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);
    return count;
}

/*!
    @brief      查询指定物理页（GPA）是否已�?
Hook 占用�?
    @details    导出给同层服务（NpBreakPoint）做同页占用检查：
                同一 4KB 页只允许一�?无痕占用�?（Hook 或断点）�?                避免两个模块互相覆盖 NPT 叶子导致状态机混乱�?
    @param[in]  PageGpa - 页对齐的客机物理地址�?
    @return     TRUE 已被 Hook；FALSE 空闲�? */
_Use_decl_annotations_
BOOLEAN
NpHookIsPageHooked(
    ULONG_PTR PageGpa)
{
    KIRQL oldIrql;
    BOOLEAN hooked;

    hooked = FALSE;
    KeAcquireSpinLock(&g_HookListLock, &oldIrql);
    if (NpHookFindHookByPage(PageGpa) != nullptr)
    {
        hooked = TRUE;
    }
    KeReleaseSpinLock(&g_HookListLock, oldIrql);
    return hooked;
}
