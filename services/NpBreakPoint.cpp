/*!
    @file       NpBreakPoint.cpp

    @brief      services/NpBreakPoint：基于 AMD NPT 的无痕断点 / NPT 监视
                （模拟硬件断点）服务模块。

    @details    ==================== 一、无痕 INT3 断点 ====================
                断点不修改任何 Guest 内存字节：
                - 读目标地址 → 永远看到原始指令（影子页0 干净拷贝）；
                - CPU 取指 → NPT NX 陷阱 → 切影子页1（入口为 0xCC）→
                  #BP VMEXIT → VMM 接管。

                每 CPU 状态机（与 NpHook 共用 NPT 叶子基础设施）：
                  A（默认）   ：GPA → 影子页0（干净拷贝），NX=1
                  B（触发中） ：GPA → 影子页1（CC 拷贝），NX=0
                  C（单步中） ：GPA → 影子页0，NX=0，RFLAGS.TF=1

                命中行为（Flags）：
                - 默认（自动单步）：记录现场 → RIP 回退断点 → 影子页0
                  可执行 + TF → 执行原指令一条 → #DB → 重新武装（持续）
                  或解除（NPHV_BP_FLAG_ONESHOT）；
                - HALT：记录现场 → RIP 回退断点 → 保持 NX 钉住线程 →
                  IOCTL/vmmcall 继续 → 单步原指令 → 重新武装。

                ==================== 二、NPT 监视（模拟硬件断点） ====================
                撤销目标页 R/W 位 → 数据访问 #NPF → 记录 → 恢复权限 →
                TF 单步 → #DB → 重新收紧。不占 DR0-DR3，数量仅受
                NPTHOOK_MAX_SPLIT_PT_PER_CPU 与内存限制。

                AMD 与 Intel 差异（参考 kanxue 帖子 + AMD APM）：
                1. NPT 无 execute-only 页 → 无痕 INT3 用双影子页实现；
                2. AMD SVM 无 Intel MTF → 单步用 RFLAGS.TF + #DB 拦截；
                3. #BP 被拦截时 VMCB.Rip 指向 INT3 本身（Intel 是 rip-1）；
                4. 读监视（清 R 位）会同时拦截取指（AMD 无 X-only 组合）。

                ==================== 三、卸载安全 ====================
                与 NpHook 相同：跳板/影子页可能正被其他 CPU 执行，
                卸载时延迟释放（退休链表），去虚拟化后统一释放。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpBreakPoint.h"
#include "NpHook.h"
#include "NpAsm.h"
#include "NpPseudoDbg.h"
#include "NpMemAccess.h"
#include <intrin.h>

// PsGetProcessPeb 未在 WDK 头声明（ntoskrnl 导出符号）。
extern "C" PVOID PsGetProcessPeb(PEPROCESS Process);

//
// ============================ 常量 ============================
//

#define X86_RFLAGS_TF               0x100           // Trap Flag

#define PAGE_ALIGN_DOWN(x)          ((x) & ~(ULONG_PTR)0xFFF)
#define PAGE_OFFSET(x)              ((x) & 0xFFF)

// 断点池标签
#define NP_BP_POOL_TAG              'pBpN'

// 断点页取指策略：
//   1 = 取指即整页切 CC 副本页（保证命中；目标自读该页时能看到断点偏移
//       处的 0xCC，隐蔽性略降）
//   0 = 保持干净页 + TF 单步逼近（自读看不到 CC，隐蔽性强；但 syscall
//       清 TF 等场景可能漏命中）
#define NP_BP_PAGE_CC_ON_IFETCH     1

//
// ============================ 数据结构 ============================
//

// 断点：无痕 INT3。影子页0 = 干净拷贝（读视图），影子页1 = CC 拷贝（执行视图）。
// 断点页记录：同一 4KB 页上的全部断点共享一组影子页与同一条 NPT 叶子。
// 影子页1（执行视图）合并该页所有活动断点偏移处的 0xCC；影子页0 恒为干净
// 副本。MDL / 进程引用同样页级共享——每页只 pin 一次，避免同页 N 个断点
// 产生 N 个 MDL（锁页只减不增，守住 0x76 不变量）。
typedef struct _BREAKPOINT_PAGE
{
    LIST_ENTRY ListEntry;           // g_BpPageListHead / g_RetiredBpPageList
    ULONG_PTR PageGpa;              // 页 GPA（页对齐）
    PEPROCESS OwnerProcess;         // 用户态：目标进程引用（页级一次）
    PMDL UserPageMdl;               // 用户态：pin 住目标物理页（页级一次）
    PVOID ShadowPage0;              // 干净拷贝（默认视图，NX=1）
    PVOID ShadowPage1;              // CC 拷贝（执行视图，合并全部断点偏移）
    ULONG_PTR ShadowPage0PA;
    ULONG_PTR ShadowPage1PA;
    ULONG RefCount;                 // 该页活动断点数（归零即待回收）
    LIST_ENTRY BpListHead;          // 该页断点链（BREAKPOINT_INFO.PageLink）
} BREAKPOINT_PAGE, *PBREAKPOINT_PAGE;

// 断点从页记录摘除后的后续动作（调用方据此决定叶子怎么处理）。
typedef enum _NP_BP_DETACH_RESULT
{
    NpBpDetachAlready = 0,          // 已摘除过：不要动叶子
    NpBpDetachLastOnPage,           // 该页最后一个断点：恢复恒等映射
    NpBpDetachMoreOnPage            // 页上还有断点：重建 CC 并重新武装
} NP_BP_DETACH_RESULT;

typedef struct _BREAKPOINT_INFO
{
    LIST_ENTRY ListEntry;           // 活动断点链表 / 退休链表
    ULONG BpId;
    BOOLEAN Active;
    ULONG Flags;                    // NPHV_BP_FLAG_*
    PBREAKPOINT_PAGE Page;          // 所属页记录（影子页/MDL/进程引用都在页级）
    LIST_ENTRY PageLink;            // 挂 Page->BpListHead
    PEPROCESS OwnerProcess;         // 【别名】== Page->OwnerProcess，勿单独释放
    ULONG_PTR Address;              // 断点 VA（内核地址）
    ULONG_PTR PageGpa;              // 【别名】== Page->PageGpa
    ULONG PageOffset;               // 页内偏移
    PVOID ShadowPage0;              // 【别名】== Page->ShadowPage0（同页共享）
    PVOID ShadowPage1;              // 【别名】== Page->ShadowPage1（同页共享）
    ULONG_PTR ShadowPage0PA;        // 【别名】== Page->ShadowPage0PA
    ULONG_PTR ShadowPage1PA;        // 【别名】== Page->ShadowPage1PA
    PMDL UserPageMdl;               // 【别名】== Page->UserPageMdl，勿单独解锁

    volatile ULONG64 HitCount;      // 累计命中次数
    ULONG LastHitCpu;               // 最近命中的 CPU
    ULONG64 LastHitCr3;             // 最近命中时的 CR3（进程标识）
    ULONG64 LastHitRip;             // 最近命中时的 RIP（INT3 地址）
    ULONG64 LastHitRflags;
    GUEST_REGISTERS LastRegisters;  // 最近命中时的通用寄存器现场

    volatile BOOLEAN Halted;        // HALT 模式：线程被钉住
    ULONG HaltCpu;                  // 被钉住的 CPU

    volatile BOOLEAN DebuggerPaused;// DEBUGGER 模式：命中后等待调试器继续。
                                    // 暂停期间保持 NX=1（其它线程/核继续
                                    // 命中）；仅暂停线程 continue 取指时由
                                    // #NPF 特判放行一次。恢复断点（重写
                                    // 0xCC）时清位并重新武装。
    ULONG DebuggerPausedThreads[8]; // 暂停线程集合（continue 单步特判）
    ULONG DebuggerPausedCount;
    volatile BOOLEAN DeletePending; // 暂停中写回原字节：待确认删除/continue 恢复
    volatile BOOLEAN StepOverSeen;  // 本次暂停期内观察到调试器的 step-over
                                    // 准备动作（写回原字节）。见
                                    // NpBreakPointReapZombieOnContinue：
                                    // 调试器若仍认这个断点，恢复前必然先把
                                    // 原字节写回再单步、然后重写 0xCC；
                                    // 完全没有这一步 = 调试器已不认它。
} BREAKPOINT_INFO, *PBREAKPOINT_INFO;

// 监视：数据访问陷阱（模拟硬件断点）。普通监视直接改原页 R/W 位；
// PEB 影子监视用干净副本页（写陷阱命中后同步影子，不周期写真实 PEB）。
typedef struct _MONITOR_INFO
{
    LIST_ENTRY ListEntry;
    ULONG MonitorId;
    BOOLEAN Active;
    ULONG AccessType;               // NPHV_MON_ACCESS_*
    ULONG_PTR Address;              // 目标 VA（信息展示用）
    ULONG_PTR PageGpa;              // 监视页 GPA（页对齐）

    // PEB shadow: NPT redirects the real PEB page to a clean copy,
    // so debugger-visible PEB fields never have to be written back.
    BOOLEAN IsPebShadow;
    BOOLEAN IsLdrShadow;
    PVOID OwnerProcess;             // PEPROCESS (refcounted at install)
    PVOID ShadowPage;               // clean copy (non-paged pool)
    ULONG_PTR ShadowPagePA;         // physical address of copy

    volatile ULONG64 HitCount;
    ULONG LastHitCpu;
    ULONG64 LastHitCr2;             // 最近命中时的 CR2（访问 GVA，若有映射）
} MONITOR_INFO, *PMONITOR_INFO;

// 每 CPU 状态（挂 VIRTUAL_PROCESSOR_DATA.ServiceData）。
typedef struct _NP_BP_CPU_STATE
{
    BOOLEAN SingleStepActive;       // 本 CPU 正在单步（TF 已置，等 #DB）
    BOOLEAN SingleStepIsMonitor;    // 单步所有者是监视（否则是断点）
    PVOID SingleStepOwner;          // PBREAKPOINT_INFO 或 PMONITOR_INFO

    //
    // DR 硬件断点虚拟化（drprobe）。
    //
    BOOLEAN DrProbeEnabled;         // 本 CPU 拦截 DR 读写中
    ULONG64 FakeDr0, FakeDr1, FakeDr2, FakeDr3;   // 假 DR（Guest 最后写入）
    ULONG64 FakeDr6, FakeDr7;
    ULONG64 PendingAddresses[4];    // DR7 使能槽对应的断点地址
    ULONG64 PendingTypes[4];        // 对应槽的访问类型（NPHV_DR_RW_*）
    ULONG PendingCount;

    // CC 副本页快速收紧（缩小 CC 自读窗口）：
    BOOLEAN BpCcDirty;              // 本 CPU 有断点页停在 CC 副本态
    BOOLEAN BpCcJustArmed;          // 本次退出刚切到 CC 副本（跳过立即复位）
} NP_BP_CPU_STATE, *PNP_BP_CPU_STATE;

//
// ============================ 全局 ============================
//

static LIST_ENTRY g_BpListHead;
static LIST_ENTRY g_MonitorListHead;
static LIST_ENTRY g_RetiredBpList;          // 退休断点（延迟释放）
static LIST_ENTRY g_RetiredMonitorList;     // 退休监视
static LIST_ENTRY g_BpPageListHead;         // 断点页记录（页级共享影子）
static LIST_ENTRY g_RetiredBpPageList;      // 退休断点页（延迟释放）
static KSPIN_LOCK g_BpListLock;             // 保护断点活动链 + 退休链
static KSPIN_LOCK g_MonitorListLock;
static PVOID NpAllocateContiguousPage(void) {
    PHYSICAL_ADDRESS high;
    high.QuadPart = (LONGLONG)-1;
    return MmAllocateContiguousMemory(PAGE_SIZE, high);
}
        // 保护监视活动链 + 退休链
static KEVENT g_BpSweepEvent;
static HANDLE g_BpSweepThread = nullptr;
static volatile BOOLEAN g_BpSweepExit = FALSE;
static volatile BOOLEAN g_BpSweepExited = FALSE; // thread has terminated
static volatile ULONG g_NextBpId = 1;
static BOOLEAN g_LegacyProcessNotify = FALSE;   // Ex 注册失败，走了 legacy 兜底
static volatile ULONG g_NextMonitorId = 1;

//
// ============================ 小工具 ============================
//

static
PNP_BP_CPU_STATE
NpGetCpuState(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    return static_cast<PNP_BP_CPU_STATE>(VpData->ServiceData);
}

//
// 扫描全部 CPU 的单步状态，判断 Owner 是否正被单步引用。
// 必须在 g_BpListLock/g_MonitorListLock 内调用：#BP/#DB handler 在同一把
// 锁内设置/清除 SingleStepOwner，持锁扫描与释放动作才构成互斥——
// 否则"扫描说不在用→释放"与"刚进入单步→#DB 引用"竞态 → UAF。
// （调用方需保证传入与对应链表匹配的锁已持有；本函数只读 ServiceData。）
//
static
BOOLEAN
NpBpIsSingleStepOwned(
    _In_ PVOID Owner)
{
    for (ULONG i = 0; i < NpHvGetProcessorCount(); i++)
    {
        PVIRTUAL_PROCESSOR_DATA vp = nullptr;
        if (!NT_SUCCESS(NpHvGetProcessorData(i, &vp)) || vp == nullptr)
        {
            continue;
        }
        PNP_BP_CPU_STATE cs =
            static_cast<PNP_BP_CPU_STATE>(vp->ServiceData);
        if (cs != nullptr && cs->SingleStepActive &&
            cs->SingleStepOwner == Owner)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 断点最终释放前的收尾：解锁并回收用户页 MDL（若有）。
// 仅限 PASSIVE_LEVEL 调用（所有释放路径均在 IOCTL/卸载 PASSIVE 上下文）。
//
//
// 页级资源释放（PASSIVE_LEVEL 限定）：解锁 MDL → 释放影子页 → 解引用进程。
// 顺序不可颠倒：解锁必须先于最后一次 ObDereferenceObject，否则进程删除路径
// （MmDeleteProcessAddressSpace）会看到残留锁页 → 0x76。
//
static
VOID
NpBpPageFreeResources(
    _In_ PBREAKPOINT_PAGE Page)
{
    if (Page == nullptr)
    {
        return;
    }
    if (Page->UserPageMdl != nullptr)
    {
        MmUnlockPages(Page->UserPageMdl);
        IoFreeMdl(Page->UserPageMdl);
        Page->UserPageMdl = nullptr;
    }
    if (Page->ShadowPage0 != nullptr)
    {
        ExFreePoolWithTag(Page->ShadowPage0, NP_BP_POOL_TAG);
        Page->ShadowPage0 = nullptr;
    }
    if (Page->ShadowPage1 != nullptr)
    {
        ExFreePoolWithTag(Page->ShadowPage1, NP_BP_POOL_TAG);
        Page->ShadowPage1 = nullptr;
    }
    if (Page->OwnerProcess != nullptr)
    {
        ObDereferenceObject(Page->OwnerProcess);
        Page->OwnerProcess = nullptr;
    }
    ExFreePoolWithTag(Page, NP_BP_POOL_TAG);
}

//
// ============================ 链表查找（调用方持锁） ============================
//

static
PBREAKPOINT_INFO
NpFindBreakpointByAddress(
    _In_ ULONG_PTR Address
    )
{
    PLIST_ENTRY entry;
    for (entry = g_BpListHead.Flink; entry != &g_BpListHead; entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (bp->Active && bp->Address == Address)
        {
            return bp;
        }
    }
    return nullptr;
}

static
PBREAKPOINT_INFO
NpFindBreakpointByPage(
    _In_ ULONG_PTR PageGpa
    )
{
    PLIST_ENTRY entry;
    PageGpa = PAGE_ALIGN_DOWN(PageGpa);
    for (entry = g_BpListHead.Flink; entry != &g_BpListHead; entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (bp->Active && bp->PageGpa == PageGpa)
        {
            return bp;
        }
    }
    return nullptr;
}

static
PBREAKPOINT_INFO
NpFindBreakpointById(
    _In_ ULONG BpId
    )
{
    PLIST_ENTRY entry;
    for (entry = g_BpListHead.Flink; entry != &g_BpListHead; entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (bp->BpId == BpId)
        {
            return bp;
        }
    }
    return nullptr;
}

static
PMONITOR_INFO
NpFindMonitorByPage(
    _In_ ULONG_PTR PageGpa
    )
{
    PLIST_ENTRY entry;
    PageGpa = PAGE_ALIGN_DOWN(PageGpa);
    for (entry = g_MonitorListHead.Flink; entry != &g_MonitorListHead; entry = entry->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(entry, MONITOR_INFO, ListEntry);
        if (mon->Active && mon->PageGpa == PageGpa)
        {
            return mon;
        }
    }
    return nullptr;
}

static
PMONITOR_INFO
NpFindMonitorById(
    _In_ ULONG MonitorId
    )
{
    PLIST_ENTRY entry;
    for (entry = g_MonitorListHead.Flink; entry != &g_MonitorListHead; entry = entry->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(entry, MONITOR_INFO, ListEntry);
        if (mon->MonitorId == MonitorId)
        {
            return mon;
        }
    }
    return nullptr;
}

//
// ==================== 断点页记录（页级共享影子 / 同页多断点） ====================
//
// 以下函数除 NpBpPageRebuildCc 外，均要求调用方持有 g_BpListLock。
//

static
PBREAKPOINT_PAGE
NpFindPageByGpa(
    _In_ ULONG_PTR PageGpa
    )
{
    PLIST_ENTRY entry;
    PageGpa = PAGE_ALIGN_DOWN(PageGpa);
    for (entry = g_BpPageListHead.Flink;
         entry != &g_BpPageListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_PAGE page = CONTAINING_RECORD(entry, BREAKPOINT_PAGE,
                                                  ListEntry);
        if (page->PageGpa == PageGpa)
        {
            return page;
        }
    }
    return nullptr;
}

// 影子页内容变更后失效全部核的缓存视图（PASSIVE/DISPATCH 均可，但必须在
// 释放 g_BpListLock 之后调用）。跨核 ICache 不自同步，不失效则其它核可能
// 继续执行旧的影子字节。
static
VOID
NpBpInvalidateShadowCaches(
    _In_ PBREAKPOINT_PAGE Page)
{
    if (Page == nullptr)
    {
        return;
    }
    if (Page->ShadowPage1 != nullptr)
    {
        KeInvalidateRangeAllCaches(Page->ShadowPage1, PAGE_SIZE);
    }
    if (Page->ShadowPage0 != nullptr)
    {
        KeInvalidateRangeAllCaches(Page->ShadowPage0, PAGE_SIZE);
    }
}

// 重建页的 CC 副本：影子页0 整页拷入影子页1，再按该页全部活动断点偏移打
// 0xCC。增删断点后必须调用，否则执行视图与断点集合不一致（漏命中/误命中）。
static
VOID
NpBpPageRebuildCc(
    _In_ PBREAKPOINT_PAGE Page)
{
    PLIST_ENTRY entry;

    if (Page == nullptr || Page->ShadowPage0 == nullptr ||
        Page->ShadowPage1 == nullptr)
    {
        return;
    }
    RtlCopyMemory(Page->ShadowPage1, Page->ShadowPage0, PAGE_SIZE);
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (bp->Active)
        {
            static_cast<PUCHAR>(Page->ShadowPage1)[bp->PageOffset] = 0xCC;
        }
    }
    //
    // 注：跨核缓存失效不在这里做。本函数会在自旋锁（DISPATCH_LEVEL）内被
    // 调用，而 KeInvalidateRangeAllCaches 会发 IPI 等待其它核应答，持锁调用
    // 有死锁风险。调用方在释放锁之后显式调用 NpBpInvalidateShadowCaches。
    //
}

// 把断点挂到页记录并填充别名。
static
VOID
NpBpAttachToPage(
    _In_ PBREAKPOINT_INFO Bp,
    _In_ PBREAKPOINT_PAGE Page)
{
    Bp->Page = Page;
    Bp->PageGpa = Page->PageGpa;
    Bp->ShadowPage0 = Page->ShadowPage0;
    Bp->ShadowPage1 = Page->ShadowPage1;
    Bp->ShadowPage0PA = Page->ShadowPage0PA;
    Bp->ShadowPage1PA = Page->ShadowPage1PA;
    Bp->UserPageMdl = Page->UserPageMdl;
    Bp->OwnerProcess = Page->OwnerProcess;
    InsertTailList(&Page->BpListHead, &Bp->PageLink);
    Page->RefCount++;
}

// 把断点从页记录摘除；页引用归零时把页记录转入退休链（资源由
// NpBreakPointFreeRetired / Teardown 在 PASSIVE 释放）。
static
NP_BP_DETACH_RESULT
NpBpDetachFromPage(
    _In_ PBREAKPOINT_INFO Bp)
{
    PBREAKPOINT_PAGE page = Bp->Page;

    if (page == nullptr)
    {
        return NpBpDetachAlready;
    }
    RemoveEntryList(&Bp->PageLink);
    Bp->Page = nullptr;
    if (page->RefCount > 0)
    {
        page->RefCount--;
    }
    if (page->RefCount == 0)
    {
        RemoveEntryList(&page->ListEntry);
        InsertTailList(&g_RetiredBpPageList, &page->ListEntry);
        return NpBpDetachLastOnPage;
    }
    return NpBpDetachMoreOnPage;
}

static
PBREAKPOINT_INFO
NpBpPageFindHalted(
    _In_ PBREAKPOINT_PAGE Page)
{
    PLIST_ENTRY entry;
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (bp->Active && bp->Halted)
        {
            return bp;
        }
    }
    return nullptr;
}

// continue 单步窗口：暂停断点地址（或 +1）取指，且取指线程在其暂停集合中。
static
PBREAKPOINT_INFO
NpBpPageFindPausedContinue(
    _In_ PBREAKPOINT_PAGE Page,
    _In_ ULONG_PTR FaultRip,
    _In_ ULONG ThreadId)
{
    PLIST_ENTRY entry;
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (!bp->Active || !bp->DebuggerPaused)
        {
            continue;
        }
        if (FaultRip != bp->Address && FaultRip != bp->Address + 1)
        {
            continue;
        }
        for (ULONG q = 0; q < bp->DebuggerPausedCount; q++)
        {
            if (bp->DebuggerPausedThreads[q] == ThreadId)
            {
                return bp;
            }
        }
    }
    return nullptr;
}

static
PBREAKPOINT_INFO
NpBpPageFindDeletePending(
    _In_ PBREAKPOINT_PAGE Page)
{
    PLIST_ENTRY entry;
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (bp->DeletePending)
        {
            return bp;
        }
    }
    return nullptr;
}

// 页内是否有断点处于调试器暂停中（复位线程据此跳过，避免提前收紧导致粘住）。
static
BOOLEAN
NpBpPageHasPaused(
    _In_ PBREAKPOINT_PAGE Page)
{
    PLIST_ENTRY entry;
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (bp->Active && bp->DebuggerPaused)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 页内首个活动断点。两处使用：
//   1. "干净页 + TF 单步"模式下登记单步所有者（页级共享叶子，具体挂到哪一个
//      不影响正确性，复位线程只按"所有者所属页"判断）；
//   2. #NPF 诊断日志里打印断点地址，便于比对 faultRip。
//
static
PBREAKPOINT_INFO
NpBpPageFindFirstActive(
    _In_ PBREAKPOINT_PAGE Page)
{
    PLIST_ENTRY entry;
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (bp->Active)
        {
            return bp;
        }
    }
    return nullptr;
}

static
PBREAKPOINT_INFO
NpBpPageFindByAddress(
    _In_ PBREAKPOINT_PAGE Page,
    _In_ ULONG_PTR Address)
{
    PLIST_ENTRY entry;
    for (entry = Page->BpListHead.Flink;
         entry != &Page->BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                PageLink);
        if (bp->Active && bp->Address == Address)
        {
            return bp;
        }
    }
    return nullptr;
}

//
// ============================ 监视叶子操作 ============================
//
// 与 NpHookSetLeaf 的区别：需要控制 R 位（Present）。NPT_ENTRY 字段
// 与 x64 页表一致（AMD NPT 友好点），直接构造后原子交换。
//

//
// ============================ PEB shadow helpers ============================
//

// Keep the PEB shadow's debug fingerprint fields clean. The shadow is snapshotted
// from the real page at install time; #DB write-trap context must NOT do physical
// reads (MmGetVirtualForPhysical returns garbage VAs for non-system-mapped frames
// and the fault cannot be SEH-caught, MmCopyMemory has IRQL constraints). The
// fields that matter for hiding are only BeingDebugged / NtGlobalFlag heap flags.
static
VOID
NpMonSyncPebShadow(
    _In_ PMONITOR_INFO Monitor)
{
    if (Monitor->IsLdrShadow) return;
    if (Monitor->ShadowPage == nullptr)
    {
        return;
    }
    *(volatile UCHAR *)((PUCHAR)Monitor->ShadowPage + 0x02) = 0;         // BeingDebugged
    *(volatile ULONG *)((PUCHAR)Monitor->ShadowPage + 0xBC) &= ~0x70UL;  // NtGlobalFlag heap flags
}

// Final release for a PEB-shadow monitor: free the shadow page and drop the
// process reference. PASSIVE_LEVEL only (same constraint as
// NpBpPageFreeResources, which must run below DISPATCH_LEVEL).
static
VOID
NpMonFinalRelease(
    _In_ PMONITOR_INFO Monitor)
{
    if (Monitor->IsPebShadow)
    {
        if (Monitor->ShadowPage != nullptr)
        {
            ExFreePoolWithTag(Monitor->ShadowPage, NP_BP_POOL_TAG);
            Monitor->ShadowPage = nullptr;
        }
        if (Monitor->OwnerProcess != nullptr)
        {
            ObDereferenceObject(static_cast<PEPROCESS>(Monitor->OwnerProcess));
            Monitor->OwnerProcess = nullptr;
        }
    }
    else if (Monitor->IsLdrShadow)
    {
        if (Monitor->ShadowPage != nullptr)
        {
            MmFreeContiguousMemory(Monitor->ShadowPage);
            Monitor->ShadowPage = nullptr;
        }
        // LDR shadows have no OwnerProcess ref
    }
}

static
VOID
NpSetMonitorLeaf(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PMONITOR_INFO Monitor,
    _In_ BOOLEAN Tighten
    )
{
    PNPT_ENTRY leaf;

    if (NpHookGetLeafEntry(VpData->NptRoot, Monitor->PageGpa, &leaf) == FALSE)
    {
        return;
    }

    NPT_ENTRY newEntry;
    newEntry.AsUInt64 = 0;
    newEntry.Fields.Present = 1;
    newEntry.Fields.Write = 1;
    newEntry.Fields.User = 1;
    newEntry.Fields.Accessed = 1;
    newEntry.Fields.Dirty = 1;
    newEntry.Fields.NoExecute = 0;

    if (Monitor->IsLdrShadow)
    {
        // LDR shadow: redirect read view to clean copy that has Flink/Blink patched to skip us
        newEntry.Fields.PageFrameNumber =
            (Tighten ? Monitor->ShadowPagePA : Monitor->PageGpa) >> 12;
        // keep original permissions (Present=1 Write=1)
    }
    else if (Monitor->IsPebShadow)
    {
        // Tight = clean copy (W=0, NX=1); release = real page (W=1, NX=1).
        newEntry.Fields.PageFrameNumber =
            (Tighten ? Monitor->ShadowPagePA : Monitor->PageGpa) >> 12;
        newEntry.Fields.NoExecute = 1;
        if (Tighten != FALSE)
        {
            newEntry.Fields.Write = 0;
        }
    }
    else
    {
        newEntry.Fields.PageFrameNumber = Monitor->PageGpa >> 12;
        if (Tighten != FALSE)
        {
            if (Monitor->AccessType & NPHV_MON_ACCESS_WRITE)
            {
                newEntry.Fields.Write = 0;
            }
            if (Monitor->AccessType & NPHV_MON_ACCESS_READ)
            {
                newEntry.Fields.Present = 0;
            }
        }
    }

    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(leaf),
                          newEntry.AsUInt64);
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;
}

//
// ============================ 单步（AMD 无 MTF，用 RFLAGS.TF + #DB） ============================
//

static
VOID
NpStartSingleStep(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PNP_BP_CPU_STATE CpuState,
    _In_ PVOID Owner,
    _In_ BOOLEAN IsMonitor
    )
{
    CpuState->SingleStepActive = TRUE;
    CpuState->SingleStepOwner = Owner;
    CpuState->SingleStepIsMonitor = IsMonitor;
    VpData->GuestVmcb.StateSaveArea.Rflags |= X86_RFLAGS_TF;
}

//
// ============================ DR 硬件断点虚拟化（drprobe） ============================
//
// SVM 拦截 DR 读写后，VMCB 提供 Guest 指令取指缓冲区
// （GuestInstructionBytes + NumOfBytesFetched），可解码出 mov 指令的
// 源/目的寄存器（ModRM.rm + REX.R）。
//

// 从 GUEST_REGISTERS 取指定寄存器（0-15，x64 编号序）的值指针。
static
PULONG64
NpRegPtr(
    _Inout_ PGUEST_REGISTERS Regs,
    _In_ ULONG Index
    )
{
    switch (Index)
    {
    case 0:  return &Regs->Rax;
    case 1:  return &Regs->Rcx;
    case 2:  return &Regs->Rdx;
    case 3:  return &Regs->Rbx;
    case 4:  return &Regs->Rsp;
    case 5:  return &Regs->Rbp;
    case 6:  return &Regs->Rsi;
    case 7:  return &Regs->Rdi;
    case 8:  return &Regs->R8;
    case 9:  return &Regs->R9;
    case 10: return &Regs->R10;
    case 11: return &Regs->R11;
    case 12: return &Regs->R12;
    case 13: return &Regs->R13;
    case 14: return &Regs->R14;
    case 15: return &Regs->R15;
    default: return nullptr;
    }
}

/*!
    @brief      从 Guest 指令取指缓冲解码 DR 访问指令。

    @details    支持：REX(.W) 0F 21 /r（mov r64,drN，读）与
                REX(.W) 0F 23 /r（mov drN,r64，写）。
                寄存器解码遵循 AMD/Intel 编码：
                - ModRM.rm + REX.B(0x01) → GPR（0-15）；
                - ModRM.reg（3 位）→ DR 编号（0-7，REX.R 对 DR 无意义，
                  因 DR 仅 8 个；x64 下 DR4/5 在 CR4.DE=0 时 #UD）。

    @param[in]  VpData - 每 CPU 数据（取 GuestInstructionBytes）。
    @param[out] OutReg - GPR 号（0-15）。
    @param[out] OutDr  - DR 编号（0-7）。
    @param[out] OutIsRead - TRUE=mov r,dr；FALSE=mov dr,r。

    @return     TRUE 解码成功；FALSE 无法识别（按通用约定处理）。
 */
static
BOOLEAN
NpDecodeDrAccess(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Out_ PULONG OutReg,
    _Out_ PULONG OutDr,
    _Out_ PBOOLEAN OutIsRead
    )
{
    PUCHAR bytes = VpData->GuestVmcb.ControlArea.GuestInstructionBytes;
    ULONG len = VpData->GuestVmcb.ControlArea.NumOfBytesFetched;
    ULONG i = 0;
    UCHAR rex = 0;

    //
    // 找 0F 21 / 0F 23 序列，记录紧邻前缀 REX。
    //
    while (i + 2 < len)
    {
        if (bytes[i] == 0x0F && (bytes[i + 1] == 0x21 || bytes[i + 1] == 0x23))
        {
            UCHAR modrm;
            ULONG reg, rm;

            if (i + 3 > len)
            {
                return FALSE;               // ModRM 未取到
            }
            rex = 0;
            if (i >= 1 && (bytes[i - 1] & 0xF0) == 0x40)
            {
                rex = bytes[i - 1];         // REX 前缀紧邻 0F
            }

            modrm = bytes[i + 2];
            reg = (modrm >> 3) & 7;         // reg 字段 = DR 编号（0-7）
            rm = modrm & 7;
            if (rex & 0x01)                 // REX.B：扩展 rm（GPR 8-15）
            {
                rm |= 8;
            }

            *OutReg = rm;
            *OutDr = reg;
            *OutIsRead = (bytes[i + 1] == 0x21);
            return TRUE;
        }
        i++;
    }
    return FALSE;
}

/*!
    @brief      DR 访问通用处理器（由 14 个 VMEXIT_DR* handler 调用）。

    @details    drprobe 开启时：
                - 写 DR0-3：记录假 DR，并解析 DR7 使能槽 → Pending 列表；
                - 写 DR7：记录假 DR7，重算 Pending（使能槽/访问类型/地址）；
                - 写 DR6：记录（忽略语义）；
                - 读 DR：回显假 DR（调试器以为断点已生效）。
                drprobe 关闭时本函数不会被调用（VMCB 未拦截）。

    @param[in]  ExitCode - VMEXIT_DR*（决定哪个寄存器、读或写）。
 */
_Use_decl_annotations_
BOOLEAN
NpBreakPointHandleDrAccess(
    PVIRTUAL_PROCESSOR_DATA VpData,
    PGUEST_CONTEXT GuestContext,
    ULONG ExitCode)
{
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    ULONG regIndex = 0;
    ULONG drIndex = 0;
    BOOLEAN isRead = FALSE;
    ULONG slot;

    if (cpuState == nullptr)
    {
        return FALSE;
    }

    //
    // 从 exit code 得出 DR 编号与读写方向（AMD 编码：Read 0x20-0x27，
    // Write 0x30-0x37，均对应 DR0-7）。
    //
    if (ExitCode >= VMEXIT_DR0_READ && ExitCode <= VMEXIT_DR7_READ)
    {
        drIndex = ExitCode - VMEXIT_DR0_READ;
        isRead = TRUE;
    }
    else if (ExitCode >= VMEXIT_DR0_WRITE && ExitCode <= VMEXIT_DR7_WRITE)
    {
        drIndex = ExitCode - VMEXIT_DR0_WRITE;
        isRead = FALSE;
    }
    else
    {
        return FALSE;
    }
    if (drIndex > 7)
    {
        return FALSE;
    }
    if (drIndex == 4 || drIndex == 5)
    {
        //
        // DR4/5 未设拦截位（x64 长模式下访问 DR4/5 无条件 #UD，与 CR4.DE
        // 无关），防御性吞掉并推进 RIP。
        //
        VpData->GuestVmcb.StateSaveArea.Rip =
            VpData->GuestVmcb.ControlArea.NRip;
        return TRUE;
    }

    //
    // 解码指令获取寄存器（失败时按通用约定处理，保证不破坏 Guest）。
    //
    if (NpDecodeDrAccess(VpData, &regIndex, &drIndex, &isRead) == FALSE)
    {
        //
        // 无法解码：保守处理——读写都当"未知"，直接返回（寄存器不动）。
        // 必须推进 RIP，否则 Guest 重执行 mov dr → 无限 VMEXIT。
        //
        VpData->GuestVmcb.StateSaveArea.Rip =
            VpData->GuestVmcb.ControlArea.NRip;
        return TRUE;
    }

    PULONG64 regPtr = NpRegPtr(GuestContext->VpRegs, regIndex);
    if (regPtr == nullptr)
    {
        VpData->GuestVmcb.StateSaveArea.Rip =
            VpData->GuestVmcb.ControlArea.NRip;
        return TRUE;
    }

    if (isRead)
    {
        //
        // 读 DR：回显假 DR。
        //
        ULONG64 value = 0;
        switch (drIndex)
        {
        case 0: value = cpuState->FakeDr0; break;
        case 1: value = cpuState->FakeDr1; break;
        case 2: value = cpuState->FakeDr2; break;
        case 3: value = cpuState->FakeDr3; break;
        case 6: value = cpuState->FakeDr6; break;
        case 7: value = cpuState->FakeDr7; break;
        default: value = 0; break;
        }
        *regPtr = value;
        VpData->GuestVmcb.StateSaveArea.Rip =
            VpData->GuestVmcb.ControlArea.NRip;
        return TRUE;
    }

    //
    // 写 DR：记录假 DR。
    //
    ULONG64 value = *regPtr;
    switch (drIndex)
    {
    case 0: cpuState->FakeDr0 = value; break;
    case 1: cpuState->FakeDr1 = value; break;
    case 2: cpuState->FakeDr2 = value; break;
    case 3: cpuState->FakeDr3 = value; break;
    case 6: cpuState->FakeDr6 = value; break;
    case 7: cpuState->FakeDr7 = value; break;
    default: break;
    }

    //
    // DR7 写入（或 DR0-3 写入）后重算 Pending：使能槽 → 地址 + 类型。
    // 槽 x 使能 = DR7.Lx(bit x) | DR7.Gx(bit 4+x)（AMD/Intel DR7 布局：
    // L0-L3=bit0-3、G0-G3=bit4-7；bit8=LE、bit9=GE 不使用）。
    //
    if (drIndex == 7 || drIndex <= 3)
    {
        ULONG64 dr7 = cpuState->FakeDr7;
        cpuState->PendingCount = 0;
        for (slot = 0; slot < 4; slot++)
        {
            ULONG64 drx = 0;
            ULONG64 type = NPHV_DR_RW_EXECUTE;

            switch (slot)
            {
            case 0: drx = cpuState->FakeDr0; break;
            case 1: drx = cpuState->FakeDr1; break;
            case 2: drx = cpuState->FakeDr2; break;
            case 3: drx = cpuState->FakeDr3; break;
            }

            if ((dr7 & (1ULL << slot)) || (dr7 & (1ULL << (4 + slot))))
            {
                type = (dr7 >> (16 + slot * 4)) & 3;    // RWx 字段
                if (type != NPHV_DR_RW_IO)
                {
                    cpuState->PendingAddresses[cpuState->PendingCount] = drx;
                    cpuState->PendingTypes[cpuState->PendingCount] = type;
                    cpuState->PendingCount++;
                }
            }
        }
    }

    //
    // 模拟完成：推进 RIP 到 NRip（被拦截指令的下一条）。
    //
    VpData->GuestVmcb.StateSaveArea.Rip =
        VpData->GuestVmcb.ControlArea.NRip;
    return TRUE;
}

// 生成 16 个 DR handler 包装（DR0-7 × read/write）。
#define NP_DEFINE_DR_HANDLER(Name, Code)                                        \
    static BOOLEAN Name(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)    \
    {                                                                           \
        return NpBreakPointHandleDrAccess(VpData, Ctx, Code);                   \
    }

NP_DEFINE_DR_HANDLER(NpBpHandleDr0Read, VMEXIT_DR0_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr1Read, VMEXIT_DR1_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr2Read, VMEXIT_DR2_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr3Read, VMEXIT_DR3_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr4Read, VMEXIT_DR4_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr5Read, VMEXIT_DR5_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr6Read, VMEXIT_DR6_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr7Read, VMEXIT_DR7_READ)
NP_DEFINE_DR_HANDLER(NpBpHandleDr0Write, VMEXIT_DR0_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr1Write, VMEXIT_DR1_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr2Write, VMEXIT_DR2_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr3Write, VMEXIT_DR3_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr4Write, VMEXIT_DR4_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr5Write, VMEXIT_DR5_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr6Write, VMEXIT_DR6_WRITE)
NP_DEFINE_DR_HANDLER(NpBpHandleDr7Write, VMEXIT_DR7_WRITE)

//
// ============================ VMEXIT 处理器 ============================
//

/*!
    @brief      #NPF 处理（注册 VMEXIT_NPF）。
    @details    取指违例 → 断点状态机；数据违例 → 监视。
                未命中任何断点/监视返回 FALSE，回落给内置（NpHook）。
 */
_Use_decl_annotations_
BOOLEAN
NpBreakPointHandleNpf(
    PVIRTUAL_PROCESSOR_DATA VpData,
    PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    ULONG_PTR faultGpa = VpData->GuestVmcb.ControlArea.ExitInfo2;
    ULONG_PTR faultRip = VpData->GuestVmcb.StateSaveArea.Rip;
    ULONG errorCode = static_cast<ULONG>(
        VpData->GuestVmcb.ControlArea.ExitInfo1 & MAXUINT32);
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    KIRQL oldIrql;

    if (errorCode & NPF_ERROR_IFETCH)
    {
        //
        // ---------------- 取指违例：断点状态机（页级） ----------------
        //
        PBREAKPOINT_PAGE page;
        PBREAKPOINT_INFO bp;
        static volatile LONG s_npfDiag = 0;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        page = NpFindPageByGpa(faultGpa);
        if (page == nullptr || IsListEmpty(&page->BpListHead))
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            return FALSE;
        }
        if (InterlockedIncrement(&s_npfDiag) <= 512)
        {
            PBREAKPOINT_INFO firstBp = NpBpPageFindFirstActive(page);
            NpHvLogPrint("[bp] npf ifetch gpa=%p rip=%p bpaddr=%p "
                         "bps-on-page=%lu\n",
                         (PVOID)faultGpa, (PVOID)faultRip,
                         (firstBp != nullptr) ? (PVOID)firstBp->Address : nullptr,
                         page->RefCount);
        }

        //
        // (1) HALT 暂停：保持 NX=1 钉住线程（与单断点时代语义一致）。
        //
        bp = NpBpPageFindHalted(page);
        if (bp != nullptr)
        {
            if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
            {
                //
                // 高 IRQL 命中暂停断点：不能忙循环钉住
                // （DPC/中断上下文卡死 → watchdog 蓝屏）。
                // 降级：恢复恒等映射放行本次执行（断点临时失效），
                // 解除暂停态并记录。线程继续运行，系统不挂死。
                //
                NpHookSetLeaf(VpData, bp->PageGpa, bp->PageGpa, FALSE, TRUE);
                bp->Halted = FALSE;
                NpHvLogPrint("[bp] HALT hit at high IRQL (%u), "
                             "released (id=%u)\n",
                             KeGetCurrentIrql(), bp->BpId);
                KeReleaseSpinLock(&g_BpListLock, oldIrql);
                return TRUE;
            }
            //
            // 暂停模式：保持 NX=1（影子页0），不切页 → 线程被钉住
            // （每次重试取指都 #NPF，形成 VMM 内忙循环）。
            //
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            return TRUE;
        }

        //
        // (2) 调试器 continue：按 faultRip 在页内匹配到具体断点，且取指线程
        //     在该断点的暂停集合中 → 回卷到断点地址并放行一次原指令
        //     （影子页0 NX=0，x64dbg 的 TF 产出 #DB 投递给 Guest）。
        //     同页多断点下必须按地址区分，否则会把 A 的 continue 误判成
        //     B 的取指（A、B 共享同一条 NPT 叶子）。
        //
        {
            ULONG curTid = static_cast<ULONG>(
                reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()));

            bp = NpBpPageFindPausedContinue(page, faultRip, curTid);
            if (bp != nullptr)
            {
                static volatile LONG s_continueDiag = 0;
                if (InterlockedIncrement((volatile LONG *)&s_continueDiag) <= 32)
                {
                    NpHvLogPrint("[bp] paused continue-step cpu=%u "
                                 "faultRip=%p rewind=%p\n",
                                 VpData->CpuIndex,
                                 (PVOID)faultRip,
                                 (PVOID)bp->Address);
                }
                VpData->GuestVmcb.StateSaveArea.Rip = bp->Address;
                NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA,
                              FALSE, TRUE);
                KeReleaseSpinLock(&g_BpListLock, oldIrql);
                return TRUE;
            }
        }

        //
        // (3) 删除确认：页内存在 DeletePending 且**本轮无 step-over 迹象**
        // 的断点才确认删除。
        //
        // 背景（2026-08-29 实机日志）：step-over 的恢复步也会写回原字节
        // （置 DeletePending + StepOverSeen），随后调试器会重写 0xCC 重装。
        // 若无 !StepOverSeen 门槛，单步走时本段会在 #NPF 上抢跑把 step-over
        // 误判成真删除（uninstall id=N → install id=N+1 churn）——断点页在
        // 存在/消失间抖动，overlay 呈现随之在 CC/原字节间跳变，x64dbg CPU
        // 窗口"代码一闪一闪"（每单步一次就 churn 一次，完全吻合现象）。
        //
        // 加了门槛后：
        //   - step-over：写原字节置 StepOverSeen=TRUE → 本段跳过 → 断点保留
        //     → 重写 0xCC → ReArm 清 DeletePending+DebuggerPaused+StepOverSeen
        //     → 无 churn，overlay 恒 CC；
        //   - 暂停中删除：写原字节置 StepOverSeen=TRUE → 本段跳过 → continue
        //     时由 NpBreakPointReapZombieOnContinue 摘除（DeletePending 仍真）。
        //
        bp = NpBpPageFindDeletePending(page);
        if (bp != nullptr && !bp->StepOverSeen)
        {
            NP_BP_DETACH_RESULT detach;

            bp->Active = FALSE;
            bp->DebuggerPaused = FALSE;
            RemoveEntryList(&bp->ListEntry);
            detach = NpBpDetachFromPage(bp);
            InsertTailList(&g_RetiredBpList, &bp->ListEntry);

            if (detach == NpBpDetachMoreOnPage)
            {
                NpBpPageRebuildCc(page);
                NpHookSetLeaf(VpData, page->PageGpa, page->ShadowPage1PA,
                              FALSE, TRUE);
                if (cpuState != nullptr)
                {
                    cpuState->BpCcDirty = TRUE;
                    cpuState->BpCcJustArmed = TRUE;
                }
            }
            else
            {
                NpHookSetLeaf(VpData, bp->PageGpa, bp->PageGpa, FALSE, TRUE);
            }
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            NpHvLogPrint("[bp] delete confirmed id=%u more-on-page=%u\n",
                         bp->BpId,
                         (detach == NpBpDetachMoreOnPage) ? 1 : 0);
            return TRUE;
        }

#if NP_BP_PAGE_CC_ON_IFETCH
        //
        // 取指即切 CC 副本页（该页全部活动断点偏移处均为 INT3，其余为原
        // 字节）：线程正常执行，走到任一断点地址必然执行 INT3 → #BP，
        // 不受 syscall 清 TF / 单步链断裂影响，也不会“跑过”断点。
        //
        NpHookSetLeaf(VpData,
                      page->PageGpa,
                      page->ShadowPage1PA,
                      FALSE,
                      TRUE);
        if (cpuState != nullptr)
        {
            cpuState->BpCcDirty = TRUE;
            cpuState->BpCcJustArmed = TRUE;
        }
#else
        bp = NpBpPageFindByAddress(page, faultRip);
        if (bp != nullptr)
        {
            NpHookSetLeaf(VpData,
                          page->PageGpa,
                          page->ShadowPage1PA,
                          FALSE,
                          TRUE);
            if (cpuState != nullptr)
            {
                cpuState->BpCcDirty = TRUE;
                cpuState->BpCcJustArmed = TRUE;
            }
        }
        else
        {
            // 干净页 + TF 单步：逐指令逼近，保持自读无 CC。
            NpHookSetLeaf(VpData,
                          page->PageGpa,
                          page->ShadowPage0PA,
                          FALSE,
                          TRUE);
            if (cpuState != nullptr)
            {
                PBREAKPOINT_INFO owner = NpBpPageFindFirstActive(page);
                if (owner != nullptr)
                {
                    NpStartSingleStep(VpData, cpuState, owner, FALSE);
                }
            }
        }
#endif
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
        return TRUE;
    }

    //
    // ---------------- 数据违例：NPT 监视 ----------------
    //
    PMONITOR_INFO mon;

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    mon = NpFindMonitorByPage(faultGpa);
    if (mon == nullptr || !mon->Active)
    {
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
        return FALSE;
    }

    //
    // 记录现场。CR2 保存 Guest 页错误地址（访问的 GVA，若有页表映射）。
    //
    mon->HitCount++;
    mon->LastHitCpu = VpData->CpuIndex;
    mon->LastHitCr2 = VpData->GuestVmcb.StateSaveArea.Cr2;

    //
    // 恢复权限 → Guest 重试访问成功；同时 TF 单步，
    // 下一条指令执行后 #DB → 重新收紧（窗口仅一条指令）。
    // cpuState 为 NULL 时（初始化分配失败）退化：仅恢复权限，
    // 靠复位线程（RESET_SHADOWS）周期性重新收紧。
    //
    NpSetMonitorLeaf(VpData, mon, FALSE);
    if (cpuState != nullptr)
    {
        NpStartSingleStep(VpData, cpuState, mon, TRUE);
    }

    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    return TRUE;
}

/*!
    @brief      #BP（INT3）处理（注册 VMEXIT_EXCEPTION_BP）。
    @details    AMD 语义：拦截 #BP 时 VMCB.Rip 指向 INT3 所在地址
                （非 Intel 的 rip-1），直接按地址匹配断点。
 */
_Use_decl_annotations_
BOOLEAN
NpBreakPointHandleBreakpoint(
    PVIRTUAL_PROCESSOR_DATA VpData,
    PGUEST_CONTEXT GuestContext)
{
    ULONG_PTR rip = VpData->GuestVmcb.StateSaveArea.Rip;
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    PBREAKPOINT_INFO bp;
    KIRQL oldIrql;
    ULONG pseudoPid = 0;
    ULONG_PTR bpAddr = 0;
    ULONG bpId = 0;
    BOOLEAN matchedTrapStyle = FALSE;       // 命中在 rip-1（INT3 本身）

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);

    //
    // 两种语义都接受。
    //
    // APM Vol2 §8.2.4："#BP is a trap-type exception. The saved instruction
    // pointer points to the byte after the INT3 instruction."——按此说法，
    // 拦截时 VMCB.Rip = INT3 地址 + 1，直接用它匹配断点地址会永远落空
    // （这正是"断点下了、执行流也过了、却断不下来"的候选根因之一）。
    //
    // 但 SVM 侧又提供 nRIP（APM Vol2 §15.7.1）专供 INT3 场景，nRIP = "trap
    // style 压栈的 RIP" = INT3 之后；若 VMCB.Rip 本身就是 INT3+1，nRIP 便
    // 多余。两种资料指向不同结论，且不同微架构实现可能有别。
    //
    // 因此先按原样匹配，失败再试 rip-1。两种语义都能命中，且不会误伤：
    // rip-1 只有在断点地址确实等于它时才成立。
    //
    bp = NpFindBreakpointByAddress(rip);
    if (bp == nullptr && rip >= 1)
    {
        bp = NpFindBreakpointByAddress(rip - 1);
        if (bp != nullptr)
        {
            matchedTrapStyle = TRUE;
        }
    }
    if (bp == nullptr || !bp->Active)
    {
        //
        // 取证：这里原来是静默 return，#BP 发生了但地址不匹配时完全看不到。
        // 这正是"断点下了、执行流也过了、却断不下来"最可能的藏身处——
        // 例如影子页内容错位，0xCC 被打到了别的偏移，Guest 在别处执行到
        // INT3，rip 对不上断点地址，于是一声不吭地放过去。
        //
        static volatile LONG s_unhandledDiag = 0;
        if (InterlockedIncrement(&s_unhandledDiag) <= 64)
        {
            NpHvLogPrint("[bp] #BP UNHANDLED rip=%p active=%u (no bp at this "
                         "addr) cpu=%u\n",
                         (PVOID)rip,
                         (bp != nullptr) ? (ULONG)bp->Active : 999u,
                         VpData->CpuIndex);
        }
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
        return FALSE;                       // 回落：NpHook / 注入 Guest
    }
    NpHvLogPrint("[bp] #BP hit id=%u addr=%p pid=%lu rip=%p %s\n",
                 bp->BpId, (PVOID)bp->Address,
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                 (PVOID)rip,
                 matchedTrapStyle ? "(trap-style: rip=addr+1)" : "(rip=addr)");

    //
    // 记录现场（寄存器在 INT3 执行瞬间的 Guest 现场）。
    //
    bp->HitCount++;
    bp->LastHitCpu = VpData->CpuIndex;
    bp->LastHitCr3 = VpData->GuestVmcb.StateSaveArea.Cr3;
    bp->LastHitRip = rip;
    bp->LastHitRflags = VpData->GuestVmcb.StateSaveArea.Rflags;
    bp->LastRegisters = *GuestContext->VpRegs;

    if (bp->Flags & NPHV_BP_FLAG_DEBUGGER)
    {
        //
        // 伪附加（新架构）：目标进程在伪会话中 → 不注入 #BP（目标无调试
        // 端口，注入会崩）。改为冻结命中线程（HALT 机制钉住）+ 事件入队 +
        // 唤醒调试器 Wait；DebugContinue 再经 NpBreakPointContinue 恢复。
        //
        ULONG curPid = static_cast<ULONG>(
            reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
        if (NpPseudoDbgIsTargetAttached(curPid))
        {
            pseudoPid = curPid;
            bpAddr = bp->Address;
            bpId = bp->BpId;
            VpData->GuestVmcb.StateSaveArea.Rip = bp->Address;
            NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, TRUE, TRUE);
            bp->Halted = TRUE;
            bp->HaltCpu = VpData->CpuIndex;
        }
        else
        {
            //
            // 传统调试器透传模式（无伪会话，X64DBG 原生调试体系）：
            // 模拟"处理器执行了 INT3"——注入 #BP 前把 RIP 推进到 NRip
            // （INT3 之后），异常以该地址交付，命中链路稳定。暂停期间
            // 保持影子页0 NX=1：其它线程/核命中继续走 CC→#BP 排队；
            // continue 时调试器可能把 EIP 设回断点地址（取指 bp），也
            // 可能直接继续（取指 bp+1），两种情况都由 #NPF 暂停线程
            // 特判处理：bp 取指直接放行，bp+1 取指回卷到 bp 再执行
            // 原指令。x64dbg 自己的 TF 产出 #DB 投递给 Guest。恢复
            // 断点（重写 0xCC）时 ReArmByAddress 清暂停集合并恢复
            // NX=1。
            //
            //
            // 推进到 INT3 之后。优先用 NRip；若 NRip 为 0（CPU 不支持
            // NRIPS 或本次 VMEXIT 未填充），回退为"断点地址 + 1"（INT3
            // 是单字节指令）——否则 RIP 会被写成 0，Guest 直接跳飞。
            //
            ULONG_PTR nextRip = VpData->GuestVmcb.ControlArea.NRip;
            if (nextRip == 0)
            {
                nextRip = bp->Address + 1;
            }
            VpData->GuestVmcb.StateSaveArea.Rip = nextRip;
            NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, TRUE, TRUE);
            bp->DebuggerPaused = TRUE;
            bp->StepOverSeen = FALSE;   // 开启一轮新的"等待 step-over"观察窗口
            {
                ULONG curTid = static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()));
                if (bp->DebuggerPausedCount <
                    ARRAYSIZE(bp->DebuggerPausedThreads))
                {
                    BOOLEAN dup = FALSE;
                    for (ULONG q = 0; q < bp->DebuggerPausedCount; q++)
                    {
                        if (bp->DebuggerPausedThreads[q] == curTid)
                        {
                            dup = TRUE;
                            break;
                        }
                    }
                    if (!dup)
                    {
                        bp->DebuggerPausedThreads[
                            bp->DebuggerPausedCount++] = curTid;
                    }
                }
            }

            EVENTINJ event;
            event.AsUInt64 = 0;
            event.Fields.Vector = 3;            // #BP
            event.Fields.Type = 3;              // Exception
            event.Fields.ErrorCodeValid = 0;
            event.Fields.Valid = 1;
            VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
        }
    }
    else if (bp->Flags & NPHV_BP_FLAG_HALT)
    {
        //
        // 暂停模式：RIP 回退到断点地址，切回影子页0 并保持 NX=1。
        // 下次取指 → #NPF → handler 见 Halted 钉住线程。
        //
        VpData->GuestVmcb.StateSaveArea.Rip = bp->Address;
        NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, TRUE, TRUE);
        bp->Halted = TRUE;
        bp->HaltCpu = VpData->CpuIndex;
    }
    else
    {
        //
        // 自动单步：RIP 回退到断点地址，切影子页0（干净）可执行，
        // 置 RFLAGS.TF —— Guest 执行原指令一条后 #DB 回来。
        //
        VpData->GuestVmcb.StateSaveArea.Rip = bp->Address;
        NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, FALSE, TRUE);
        if (cpuState != nullptr)
        {
            NpStartSingleStep(VpData, cpuState, bp, FALSE);
        }
    }

    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    if (pseudoPid != 0)
    {
        NpPseudoDbgQueueBpEvent(
            pseudoPid, bpAddr,
            static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                PsGetCurrentThreadId())),
            bpId);
    }
    return TRUE;
}

/*!
    @brief      #DB（调试异常）处理（注册 VMEXIT_EXCEPTION_DB）。
    @details    仅当本 CPU 处于本框架的单步（TF 已置）时接管；
                否则回落（分发器注入 #DB 给 Guest，供其调试器使用）。
 */
_Use_decl_annotations_
BOOLEAN
NpBreakPointHandleDebug(
    PVIRTUAL_PROCESSOR_DATA VpData,
    PGUEST_CONTEXT GuestContext)
{
    UNREFERENCED_PARAMETER(GuestContext);
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    KIRQL oldIrql;

    if (cpuState == nullptr || cpuState->SingleStepActive == FALSE)
    {
        static volatile LONG s_guestDbDiag = 0;
        if (InterlockedIncrement((volatile LONG *)&s_guestDbDiag) <= 32)
        {
            NpHvLogPrint("[bp] #DB guest cpu=%u rip=%p\n",
                         VpData->CpuIndex,
                         (PVOID)VpData->GuestVmcb.StateSaveArea.Rip);
        }
        return FALSE;                       // Guest 自己的 #DB
    }

    //
    // 清除 TF（原指令已执行完，#DB 为单步回报）。
    //
    VpData->GuestVmcb.StateSaveArea.Rflags &= ~static_cast<ULONG_PTR>(X86_RFLAGS_TF);

    if (cpuState->SingleStepIsMonitor != FALSE)
    {
        //
        // 监视单步完成：重新收紧权限。
        //
        PMONITOR_INFO mon = static_cast<PMONITOR_INFO>(cpuState->SingleStepOwner);
        cpuState->SingleStepActive = FALSE;
        cpuState->SingleStepOwner = nullptr;

        KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
        if (mon->Active)
        {
            if (mon->IsPebShadow)
            {
                // The guest just wrote the real PEB page; refresh the shadow.
                NpMonSyncPebShadow(mon);
            }
            NpSetMonitorLeaf(VpData, mon, TRUE);
        }
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
        return TRUE;
    }

    //
    // 断点单步完成：原指令已执行（RIP 在其后），重新武装或解除。
    //
    PBREAKPOINT_INFO bp = static_cast<PBREAKPOINT_INFO>(cpuState->SingleStepOwner);
    cpuState->SingleStepActive = FALSE;
    cpuState->SingleStepOwner = nullptr;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    if (bp->Active)
    {
        if (bp->Flags & NPHV_BP_FLAG_ONESHOT)
        {
            //
            // 单次断点：摘除（延迟释放，VMEXIT 上下文不释放内存）。
            // 页上还有其它断点时不能恢复恒等映射，而要重建 CC 并继续
            // 武装，否则同页其余断点会被一起废掉。
            //
            PBREAKPOINT_PAGE oneshotPage = bp->Page;
            NP_BP_DETACH_RESULT detach;

            bp->Active = FALSE;
            RemoveEntryList(&bp->ListEntry);
            detach = NpBpDetachFromPage(bp);
            InsertTailList(&g_RetiredBpList, &bp->ListEntry);

            if (detach == NpBpDetachMoreOnPage && oneshotPage != nullptr)
            {
                NpBpPageRebuildCc(oneshotPage);
                NpHookSetLeaf(VpData, oneshotPage->PageGpa,
                              oneshotPage->ShadowPage1PA, FALSE, TRUE);
            }
            else
            {
                NpHookSetLeaf(VpData, bp->PageGpa, bp->PageGpa, FALSE, TRUE);
            }
        }
        else
        {
            //
            // 持续断点：重新武装（影子页0，NX=1）。下次取指重新
            // 走 NPF → CC → #BP 全流程。
            //
            NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, TRUE, TRUE);
            static volatile LONG s_stepDiag = 0;
            if (InterlockedIncrement(&s_stepDiag) <= 16)
            {
                NpHvLogPrint("[bp] step rearm id=%u rip=%p\n",
                             bp->BpId,
                             (PVOID)VpData->GuestVmcb.StateSaveArea.Rip);
            }
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    return TRUE;
}

/*!
    @brief      VMMCALL 处理（注册 VMEXIT_VMMCALL）。
    @details    - VMMCALL_BP_CONTINUE：继续被暂停的断点（本 CPU 上下文，
                  可安全修改 VMCB.Rflags 与 NPT 叶子）；
                - VMMCALL_RESET_SHADOWS：复位断点/监视页（跳过单步中的）。
                始终返回 FALSE：让内置 VMMCALL 处理器继续（更新 NRip
                与 NpHook 的影子复位）。
 */
// 复位本 CPU 全部断点/监视页（跳过单步中/暂停中）。供定时复位线程与
// 每次 VMEXIT 后的快速收紧共用。
static
VOID
NpBreakPointResetShadowsOnCpu(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    //
    // 复位本 CPU 断点页（按页遍历：同页多个断点只处理一次）：
    // 非单步中、且页内没有暂停中的断点 → 影子页0（NX=1）。
    // 单步中的页保持影子页0（NX=0），否则 TF 单步的取指会被
    // NX 拦截导致死循环。
    //
    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (entry = g_BpPageListHead.Flink;
         entry != &g_BpPageListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_PAGE page = CONTAINING_RECORD(entry, BREAKPOINT_PAGE,
                                                  ListEntry);
        if (cpuState != nullptr && cpuState->SingleStepActive &&
            cpuState->SingleStepIsMonitor == FALSE &&
            cpuState->SingleStepOwner != nullptr)
        {
            PBREAKPOINT_INFO owner =
                static_cast<PBREAKPOINT_INFO>(cpuState->SingleStepOwner);
            if (owner->Page == page)
            {
                continue;               // 本页正被单步，跳过
            }
        }
        if (NpBpPageHasPaused(page))
        {
            //
            // 暂停中保持 NX=1；continue 单步窗口（NX=0）由 #NPF 特判
            // 控制。复位线程跳过，避免在单步窗口提前收紧导致断点粘住。
            //
            continue;
        }
        NpHookSetLeaf(VpData, page->PageGpa, page->ShadowPage0PA, TRUE, TRUE);
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    //
    // 复位监视页：重新收紧（兜底，防 TF 单步丢失）。
    //
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (entry = g_MonitorListHead.Flink;
         entry != &g_MonitorListHead;
         entry = entry->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(entry, MONITOR_INFO, ListEntry);
        if (!mon->Active)
        {
            continue;
        }
        if (cpuState != nullptr && cpuState->SingleStepActive &&
            cpuState->SingleStepIsMonitor != FALSE &&
            cpuState->SingleStepOwner == mon)
        {
            continue;               // 单步中，跳过
        }
        NpSetMonitorLeaf(VpData, mon, TRUE);
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    if (cpuState != nullptr)
    {
        cpuState->BpCcDirty = FALSE;
        cpuState->BpCcJustArmed = FALSE;
    }
}

// 每次 VMEXIT 返回 Guest 前调用：若本 CPU 有断点页停在 CC 副本态，
// 立即重新武装，把 CC 自读窗口从"复位周期（1ms）"压到"下一次 VMEXIT"。
// 刚由 #NPF 切到 CC 副本的本次退出跳过（否则会在执行 INT3 前把叶子
// 收走，导致取指重入死循环）。
static
VOID
NpBreakPointPostExit(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    if (cpuState == nullptr)
    {
        return;
    }
    if (cpuState->BpCcJustArmed)
    {
        cpuState->BpCcJustArmed = FALSE;
        return;
    }
    if (!cpuState->BpCcDirty)
    {
        return;
    }
    static volatile LONG s_rearmDiag = 0;
    if (InterlockedIncrement(&s_rearmDiag) <= 32)
    {
        NpHvLogPrint("[bp] cc rearm next-exit cpu=%u\n", VpData->CpuIndex);
    }
    NpBreakPointResetShadowsOnCpu(VpData);
}

_Use_decl_annotations_
BOOLEAN
NpBreakPointHandleVmmcall(
    PVIRTUAL_PROCESSOR_DATA VpData,
    PGUEST_CONTEXT GuestContext)
{
    ULONG code = static_cast<ULONG>(GuestContext->VpRegs->Rax & MAXUINT32);
    PNP_BP_CPU_STATE cpuState = NpGetCpuState(VpData);
    KIRQL oldIrql;

    if (code == VMMCALL_DRPROBE_SET)
    {
        //
        // 在本 CPU 自己的 VMEXIT 上下文修改 VMCB 拦截位（下次 VMRUN 生效）。
        // rcx = 0 关闭（恢复直通，零开销）；rcx != 0 开启（接管 DR）。
        //
        BOOLEAN enable = (GuestContext->VpRegs->Rcx != 0);

        VpData->GuestVmcb.ControlArea.InterceptDrRead =
            enable ? SVM_INTERCEPT_DR_ALL : 0;
        VpData->GuestVmcb.ControlArea.InterceptDrWrite =
            enable ? SVM_INTERCEPT_DR_ALL : 0;

        if (cpuState != nullptr)
        {
            cpuState->DrProbeEnabled = enable;
            if (!enable)
            {
                RtlZeroMemory(&cpuState->FakeDr0, sizeof(ULONG64) * 4);
                cpuState->FakeDr6 = 0;
                cpuState->FakeDr7 = 0;
                cpuState->PendingCount = 0;
            }
        }
        return FALSE;       // 内置处理器更新 NRip
    }

    if (code == VMMCALL_BP_CONTINUE)
    {
        ULONG64 bpId = GuestContext->VpRegs->Rcx;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        if (bpId == 0)
        {
            PLIST_ENTRY entry;
            for (entry = g_BpListHead.Flink;
                 entry != &g_BpListHead;
                 entry = entry->Flink)
            {
                PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
                if (bp->Active && bp->Halted && bp->HaltCpu == VpData->CpuIndex)
                {
                    bp->Halted = FALSE;
                    NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, FALSE, TRUE);
                    NpStartSingleStep(VpData, cpuState, bp, FALSE);
                }
            }
        }
        else
        {
            PBREAKPOINT_INFO bp = NpFindBreakpointById(static_cast<ULONG>(bpId));
            if (bp != nullptr && bp->Active && bp->Halted &&
                bp->HaltCpu == VpData->CpuIndex)
            {
                bp->Halted = FALSE;
                NpHookSetLeaf(VpData, bp->PageGpa, bp->ShadowPage0PA, FALSE, TRUE);
                NpStartSingleStep(VpData, cpuState, bp, FALSE);
            }
        }
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
        return FALSE;
    }

    if (code == VMMCALL_RESET_SHADOWS)
    {
        NpBreakPointResetShadowsOnCpu(VpData);
        return FALSE;
    }

    return FALSE;
}

//
// ============================ 每 CPU 遍历 ============================
//

typedef struct _BP_CPU_CONTEXT
{
    PBREAKPOINT_INFO Bp;
    PMONITOR_INFO Monitor;
    ULONG CpuIndex;
} BP_CPU_CONTEXT, *PBP_CPU_CONTEXT;

// 断点：状态 A（影子页0，NX=1）
static
NTSTATUS
NpBreakPointConfigureOnProcessor(
    _In_ PVOID Context
    )
{
    PBP_CPU_CONTEXT cpuContext = static_cast<PBP_CPU_CONTEXT>(Context);
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    NTSTATUS status;

    status = NpHvGetProcessorData(cpuContext->CpuIndex, &vpData);
    if (!NT_SUCCESS(status) || vpData == nullptr)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NpHookSetLeaf(vpData,
                  cpuContext->Bp->PageGpa,
                  cpuContext->Bp->ShadowPage0PA,
                  TRUE,
                  TRUE);
    return STATUS_SUCCESS;
}

// 断点：恢复恒等映射
static
NTSTATUS
NpBreakPointRestoreOnProcessor(
    _In_ PVOID Context
    )
{
    PBP_CPU_CONTEXT cpuContext = static_cast<PBP_CPU_CONTEXT>(Context);
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    NTSTATUS status;

    status = NpHvGetProcessorData(cpuContext->CpuIndex, &vpData);
    if (!NT_SUCCESS(status) || vpData == nullptr)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NpHookSetLeaf(vpData,
                  cpuContext->Bp->PageGpa,
                  cpuContext->Bp->PageGpa,
                  FALSE,
                  TRUE);
    //
    // 恢复恒等后尝试把整页合并回 2MB 大页（释放 PT 池页，防耗尽）。
    //
    NpHookTryMergeLargePage(vpData, cpuContext->Bp->PageGpa);
    return STATUS_SUCCESS;
}

// 监视：收紧权限
static
NTSTATUS
NpBreakPointMonitorConfigureOnProcessor(
    _In_ PVOID Context
    )
{
    PBP_CPU_CONTEXT cpuContext = static_cast<PBP_CPU_CONTEXT>(Context);
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    NTSTATUS status;

    status = NpHvGetProcessorData(cpuContext->CpuIndex, &vpData);
    if (!NT_SUCCESS(status) || vpData == nullptr)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NpSetMonitorLeaf(vpData, cpuContext->Monitor, TRUE);
    return STATUS_SUCCESS;
}

// 监视：恢复全权限
static
NTSTATUS
NpBreakPointMonitorRestoreOnProcessor(
    _In_ PVOID Context
    )
{
    PBP_CPU_CONTEXT cpuContext = static_cast<PBP_CPU_CONTEXT>(Context);
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    NTSTATUS status;

    status = NpHvGetProcessorData(cpuContext->CpuIndex, &vpData);
    if (!NT_SUCCESS(status) || vpData == nullptr)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NpSetMonitorLeaf(vpData, cpuContext->Monitor, FALSE);
    //
    // 恢复恒等后尝试合并回大页（释放 PT 池页）。
    //
    NpHookTryMergeLargePage(vpData, cpuContext->Monitor->PageGpa);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NpBreakPointExecuteOnEachProcessor(
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

        static_cast<PBP_CPU_CONTEXT>(Context)->CpuIndex = i;
        status = Callback(Context);

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
        {
            break;
        }
    }
    return status;
}

//
// ============================ 断点安装 / 卸载 / 查询 ============================
//

/*!
    @brief      安装一个 NPT 无痕断点（内核地址）。

    @param[in]  Address - 断点 VA（内核态）。
    @param[in]  Flags   - NPHV_BP_FLAG_*（0=自动单步模式）。
    @param[out] OutBpId - 断点句柄。

    @return     STATUS_SUCCESS 或错误码。
 */
_Use_decl_annotations_
NTSTATUS
NpBreakPointInstall(
    ULONG_PTR Address,
    ULONG Flags,
    PULONG OutBpId)
{
    return NpBreakPointInstallEx(Address, Flags, nullptr, OutBpId);
}

/*!
    @brief      安装一个 NPT 无痕断点（扩展，支持用户态地址）。

    @param[in]  Address - 断点 VA。Process 非空时可为用户态地址。
    @param[in]  Flags   - NPHV_BP_FLAG_*。
    @param[in]  Process - 目标进程（用户态地址时用于 AttachProcess 读页；
                          内核地址时传 nullptr）。引用计数由调用方管理。
    @param[out] OutBpId - 断点句柄（可为 null）。

    @return     STATUS_SUCCESS 或错误码。
 */
_Use_decl_annotations_
NTSTATUS
NpBreakPointInstallEx(
    ULONG_PTR Address,
    ULONG Flags,
    PEPROCESS Process,
    PULONG OutBpId)
{
    PBREAKPOINT_INFO bp;
    NTSTATUS status;
    PUCHAR originalPageVa;
    ULONG_PTR originalPhysical;
    KIRQL oldIrql;
    BOOLEAN attached = FALSE;
    BOOLEAN mdlLocked = FALSE;
    BOOLEAN pageCreated = FALSE;
    KAPC_STATE apcState;
    PMDL pageMdl = nullptr;
    PBREAKPOINT_PAGE page = nullptr;

    if (OutBpId != nullptr)
    {
        *OutBpId = 0;
    }
    if (Address == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 地址性质判定：Process 非空 = 用户态地址；否则必须内核态。
    //
    if (Process == nullptr)
    {
        if (Address < 0xFFFF800000000000ULL)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    originalPageVa = reinterpret_cast<PUCHAR>(PAGE_ALIGN_DOWN(Address));

    //
    // 先解析目标页 GPA（用户态需 AttachProcess 触发换入）。
    //
    if (Process != nullptr)
    {
        KeStackAttachProcess(Process, &apcState);
        attached = TRUE;
    }

    __try
    {
        if (attached)
        {
            ProbeForRead(originalPageVa, PAGE_SIZE, 1);
        }
        originalPhysical = MmGetPhysicalAddress(
            reinterpret_cast<PVOID>(originalPageVa)).QuadPart;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        originalPhysical = 0;
    }
    if (originalPhysical == 0)
    {
        status = STATUS_NOT_FOUND;          // 页不存在/换出失败
        goto ExitPre;
    }

    //
    // 与 NPT Hook 仍按页互斥（抢同一条叶子）。
    //
    if (NpHookIsPageHooked(originalPhysical))
    {
        status = STATUS_ALREADY_REGISTERED;
        goto ExitPre;
    }

    //
    // 断点之间不再互斥：查页记录决定"复用"还是"新建"。
    // 同地址重复安装 = 调试器重写 0xCC（返回 ALREADY_REGISTERED 交由调用方
    // ReArm）；同页不同地址则共享该页的影子页与 NPT 叶子。
    //
    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    page = NpFindPageByGpa(originalPhysical);
    if (page != nullptr)
    {
        if (NpBpPageFindByAddress(page, Address) != nullptr ||
            page->OwnerProcess != Process)
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            status = STATUS_ALREADY_REGISTERED;
            goto ExitPre;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    //
    // 用户态页：仅新建页记录时才 pin 物理帧（页级共享，同页第二个断点不再
    // 新建 MDL）。pin 保证断点存续期间该物理帧不被换出/重用——否则帧被内存
    // 管理器回收复用后，全 CPU 的 NPT 仍把该 GPA 重定向到影子页，任何核访问
    // 新用途的帧都会被劫持（全局内存破坏级蓝屏源）。
    // 已知限制：CoW 会换新帧，断点对私有副本静默失效（不崩溃）。
    //
    if (page == nullptr && Process != nullptr)
    {
        __try
        {
            pageMdl = IoAllocateMdl(originalPageVa, PAGE_SIZE,
                                    FALSE, FALSE, nullptr);
            if (pageMdl != nullptr)
            {
                MmProbeAndLockPages(pageMdl, KernelMode, IoReadAccess);
                mdlLocked = TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (pageMdl != nullptr)
            {
                IoFreeMdl(pageMdl);     // 锁定失败：MDL 未持页，直接回收
                pageMdl = nullptr;
            }
            status = STATUS_NOT_FOUND;
            goto ExitPre;
        }
    }

    bp = static_cast<PBREAKPOINT_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                       sizeof(BREAKPOINT_INFO),
                                                       NP_BP_POOL_TAG));
    if (bp == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitPre;
    }
    RtlZeroMemory(bp, sizeof(BREAKPOINT_INFO));

    bp->Address = Address;
    bp->PageOffset = static_cast<ULONG>(PAGE_OFFSET(Address));
    bp->Flags = Flags;

    //
    // 页记录：复用已有页（同页多断点），或为首个占用本页的断点新建。
    //
    if (page == nullptr)
    {
        page = static_cast<PBREAKPOINT_PAGE>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(BREAKPOINT_PAGE),
                            NP_BP_POOL_TAG));
        if (page == nullptr)
        {
            ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto ExitPre;
        }
        RtlZeroMemory(page, sizeof(BREAKPOINT_PAGE));
        InitializeListHead(&page->BpListHead);
        page->PageGpa = originalPhysical;
        page->UserPageMdl = pageMdl;        // 所有权移交页记录
        pageMdl = nullptr;

        if (Process != nullptr)
        {
            ObReferenceObject(Process);     // 页级持一次进程引用
            page->OwnerProcess = Process;
        }

        //
        // 影子页：0 = 干净拷贝，1 = CC 拷贝（合并该页全部断点偏移）。
        //
        page->ShadowPage0 = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE,
                                            NP_BP_POOL_TAG);
        page->ShadowPage1 = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE,
                                            NP_BP_POOL_TAG);
        if (page->ShadowPage0 == nullptr || page->ShadowPage1 == nullptr)
        {
            NpBpPageFreeResources(page);
            ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto ExitPre;
        }

        if (attached)
        {
            //
            // 用户页：AttachProcess 下拷贝原始页。
            //
            __try
            {
                ProbeForRead(originalPageVa, PAGE_SIZE, 1);
                RtlCopyMemory(page->ShadowPage0, originalPageVa, PAGE_SIZE);
                RtlCopyMemory(page->ShadowPage1, originalPageVa, PAGE_SIZE);
                status = STATUS_SUCCESS;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = STATUS_NOT_FOUND;
            }
            if (!NT_SUCCESS(status))
            {
                NpBpPageFreeResources(page);
                ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
                goto ExitPre;
            }
        }
        else
        {
            RtlCopyMemory(page->ShadowPage0, originalPageVa, PAGE_SIZE);
            RtlCopyMemory(page->ShadowPage1, originalPageVa, PAGE_SIZE);
        }

        page->ShadowPage0PA = MmGetPhysicalAddress(page->ShadowPage0).QuadPart;
        page->ShadowPage1PA = MmGetPhysicalAddress(page->ShadowPage1).QuadPart;
        pageCreated = TRUE;
    }

    //
    // 用户 VA 之后不再使用，先解附加（ExitPre 也据此判断）。
    //
    if (attached)
    {
        KeUnstackDetachProcess(&apcState);
        attached = FALSE;
    }

    //
    // 挂到页记录并重建 CC 副本（并入新断点的 0xCC；同页其它断点保持）。
    //
    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    if (pageCreated)
    {
        InsertTailList(&g_BpPageListHead, &page->ListEntry);
    }
    NpBpAttachToPage(bp, page);

    //
    // Active 必须在 RebuildCc 之前置位！
    //
    // NpBpPageRebuildCc 只对 bp->Active 的断点打 0xCC（删除路径正是靠"先把
    // Active 置 FALSE 再 Rebuild"来把 CC 清掉的）。页级共享影子重构时把
    // Active 留在 RebuildCc 之后才置位，于是新装断点的 0xCC 从未被打进
    // 影子页1 —— 断点列表正常、执行流照过、但永远命中不了，且日志无任何
    // 异常。本机取证日志 [bp] verify ... cc=0x48（应为 0xCC）直接暴露了它。
    //
    bp->Active = TRUE;
    NpBpPageRebuildCc(page);
    bp->BpId = static_cast<ULONG>(
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_NextBpId)));
    InsertTailList(&g_BpListHead, &bp->ListEntry);
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = bp;
    cpuContext.Monitor = nullptr;
    cpuContext.CpuIndex = 0;

    status = NpBreakPointExecuteOnEachProcessor(NpBreakPointConfigureOnProcessor,
                                                &cpuContext);
    if (!NT_SUCCESS(status))
    {
        NpBreakPointUninstall(bp->BpId, FALSE);
        return status;
    }

    //
    // 影子页内容变了（新断点并入 CC 副本）：失效其它核的缓存视图。
    //
    NpBpInvalidateShadowCaches(page);

    //
    // 取证：确认 0xCC 真的落在影子页1 的正确偏移上，且影子页0 同位置仍是
    // 原字节。装完就验，避免"影子错位导致断点静默失效"无法察觉。
    //
    {
        PUCHAR clean = static_cast<PUCHAR>(page->ShadowPage0);
        PUCHAR cc = static_cast<PUCHAR>(page->ShadowPage1);
        NpHvLogPrint("[bp] verify id=%u gpa=%p off=0x%03X "
                     "clean=0x%02X cc=0x%02X ccpa=%p\n",
                     bp->BpId, (PVOID)page->PageGpa, bp->PageOffset,
                     clean[bp->PageOffset], cc[bp->PageOffset],
                     (PVOID)page->ShadowPage1PA);
    }

    if (OutBpId != nullptr)
    {
        *OutBpId = bp->BpId;
    }
    NpHvLogPrint("[bp] install id=%u addr=0x%p pa=0x%llx flags=0x%x user=%u "
                 "page=%s bps-on-page=%lu\n",
                 bp->BpId,
                 reinterpret_cast<PVOID>(Address),
                 originalPhysical,
                 Flags,
                 (Process != nullptr) ? 1 : 0,
                 pageCreated ? "new" : "reuse",
                 page->RefCount);
    return STATUS_SUCCESS;

ExitPre:
    if (pageMdl != nullptr)
    {
        if (mdlLocked)
        {
            MmUnlockPages(pageMdl);
        }
        IoFreeMdl(pageMdl);
        pageMdl = nullptr;
        mdlLocked = FALSE;
    }
    if (attached)
    {
        KeUnstackDetachProcess(&apcState);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointUninstall(
    ULONG BpId,
    BOOLEAN FreeResources)
{
    PBREAKPOINT_INFO bp = nullptr;
    PBREAKPOINT_PAGE page = nullptr;
    NP_BP_DETACH_RESULT detach;
    KIRQL oldIrql;

    BOOLEAN inUse = FALSE;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointById(BpId);
    if (bp == nullptr)
    {
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
        return STATUS_NOT_FOUND;
    }
    if (!bp->Active)
    {
        // 已由 #NPF 停用的待删除断点：页资源已摘除，这里只回收结构。
        if (!bp->DeletePending)
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            return STATUS_NOT_FOUND;
        }
        RemoveEntryList(&bp->ListEntry);
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
        ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
        NpHvLogPrint("[bp] pending-delete freed id=%u\n", BpId);
        return STATUS_SUCCESS;
    }
    bp->Active = FALSE;
    RemoveEntryList(&bp->ListEntry);

    //
    // 从页记录摘除（页引用归零则页转入退休链）。
    //
    page = bp->Page;
    detach = NpBpDetachFromPage(bp);

    //
    // 单步占用检查必须与摘除同锁：#BP/#DB handler 在同一把 g_BpListLock
    // 内设置/清除 SingleStepOwner，持锁扫描才能与"刚进入单步"互斥，
    // 杜绝"扫描不在用→释放"与"#DB 引用已释放 bp"的 TOCTOU UAF。
    //
    inUse = NpBpIsSingleStepOwned(bp);
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    //
    // 叶子处理：页上还有断点 → 重建 CC（去掉本断点的 0xCC）并重新武装；
    // 本断点是最后一个 → 恢复恒等映射。
    //
    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = bp;
    cpuContext.Monitor = nullptr;
    cpuContext.CpuIndex = 0;

    if (detach == NpBpDetachMoreOnPage)
    {
        NpBpPageRebuildCc(page);
        NpBreakPointExecuteOnEachProcessor(NpBreakPointConfigureOnProcessor,
                                           &cpuContext);
        NpBpInvalidateShadowCaches(page);
    }
    else if (detach == NpBpDetachLastOnPage)
    {
        NpBreakPointExecuteOnEachProcessor(NpBreakPointRestoreOnProcessor,
                                           &cpuContext);
    }

    if (FreeResources != FALSE)
    {
        if (!inUse)
        {
            //
            // 摘除后无任何单步引用（且 Active=FALSE 后不可能再进入单步）：
            // 立即释放安全。页资源已归退休链/已释放，这里只回收 bp 结构。
            //
            ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
        }
        else
        {
            NpHvLogPrint("[bp] uninstall id=%u deferred (single-step in "
                         "progress)\n", BpId);
            KeAcquireSpinLock(&g_BpListLock, &oldIrql);
            InsertTailList(&g_RetiredBpList, &bp->ListEntry);
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
        }
    }
    else
    {
        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        InsertTailList(&g_RetiredBpList, &bp->ListEntry);
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
    }

    NpHvLogPrint("[bp] uninstall id=%u\n", BpId);
    return STATUS_SUCCESS;
}

/*!
    @brief      调试器读内存时，把断点偏移处的字节呈现为 0xCC。

    @details    解决无痕断点的固有矛盾：调试器写 0xCC 被 WVM 拦截转成 NPT
                断点（真实内存不留痕），若随后读同一地址又返回**真实字节**，
                调试器会以为"自己写的断点消失了"，于是删除断点时不再写回
                原字节 —— 驱动侧的 try-delete 探测不到删除意图，断点残留，
                取消后运行目标函数仍会被断下；调试器收到未预期的断点异常
                后目标崩溃。

                修法：仅对**已附加的调试器进程**呈现 0xCC，其它调用方（内存
                扫描、反作弊、目标自身）仍返回真实字节，无痕性不受影响。
*/
_Use_decl_annotations_
BOOLEAN
NpBreakPointOverlayCcForRead(
    ULONG TargetPid,
    ULONG_PTR StartVa,
    ULONG Length,
    PUCHAR Buffer)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    BOOLEAN applied = FALSE;

    if (Buffer == nullptr || Length == 0 || TargetPid == 0)
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (entry = g_BpListHead.Flink;
         entry != &g_BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO,
                                                ListEntry);
        if (!bp->Active || bp->OwnerProcess == nullptr)
        {
            continue;
        }
        if (HandleToULong(PsGetProcessId(
                static_cast<PEPROCESS>(bp->OwnerProcess))) != TargetPid)
        {
            continue;
        }
        if (bp->Address >= StartVa && bp->Address < StartVa + Length)
        {
            Buffer[bp->Address - StartVa] = 0xCC;
            applied = TRUE;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    return applied;
}

/*!
    @brief      非暂停期收到 0xCC 写且断点已存在：判定为删除。

    @details    x64dbg 的 `BpEnable()` 在启用断点时会用 `MemRead` **重读**
                `oldbytes`（dbg/breakpoint.cpp:403）。叠加本驱动对调试器呈现
                0xCC 的读视图，oldbytes 可能被污染成 0xCC —— 于是删除断点时
                写回的是 0xCC 而不是真正的原字节。

                这类写在 WVM 侧会走 `isInt3` 分支，被当成"重新武装断点"
                （ALREADY_REGISTERED → ReArmByAddress），结果断点永远删不掉。

                区分依据：step-over 的重新武装**必然发生在暂停期内**
                （命中 → 写原字节 → 单步 → 重写 0xCC → 继续），此时
                DebuggerPaused 为真；而删除发生在运行期，DebuggerPaused
                为假。因此非暂停期的 0xCC 重写一律判为删除。
*/
_Use_decl_annotations_
BOOLEAN
NpBreakPointDeleteByCcWrite(
    ULONG_PTR Address)
{
    PBREAKPOINT_INFO bp = nullptr;
    KIRQL oldIrql;
    ULONG bpId = 0;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointByAddress(Address);
    if (bp != nullptr && bp->Active &&
        (bp->Flags & NPHV_BP_FLAG_DEBUGGER) && !bp->DebuggerPaused)
    {
        bpId = bp->BpId;
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    if (bpId == 0)
    {
        return FALSE;
    }

    NpBreakPointUninstall(bpId, TRUE);
    NpHvLogPrint("[bp] debugger delete via 0xCC write @0x%p "
                 "(oldbytes polluted, not a step-over rearm)\n",
                 reinterpret_cast<PVOID>(Address));
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointUninstallAll(
    BOOLEAN FreeResources)
{
    KIRQL oldIrql;

    for (;;)
    {
        PBREAKPOINT_INFO bp = nullptr;
        NP_BP_DETACH_RESULT detach;
        BOOLEAN inUse = FALSE;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        if (IsListEmpty(&g_BpListHead))
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            break;
        }
        bp = CONTAINING_RECORD(g_BpListHead.Flink, BREAKPOINT_INFO, ListEntry);
        bp->Active = FALSE;
        RemoveEntryList(&bp->ListEntry);
        detach = NpBpDetachFromPage(bp);
        inUse = NpBpIsSingleStepOwned(bp);      // 同锁扫描（防 TOCTOU UAF）
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        if (detach != NpBpDetachAlready)
        {
            BP_CPU_CONTEXT cpuContext;
            cpuContext.Bp = bp;
            cpuContext.Monitor = nullptr;
            cpuContext.CpuIndex = 0;
            NpBreakPointExecuteOnEachProcessor(NpBreakPointRestoreOnProcessor,
                                               &cpuContext);
        }

        if (FreeResources != FALSE)
        {
            if (!inUse)
            {
                ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
            }
            else
            {
                KeAcquireSpinLock(&g_BpListLock, &oldIrql);
                InsertTailList(&g_RetiredBpList, &bp->ListEntry);
                KeReleaseSpinLock(&g_BpListLock, oldIrql);
            }
        }
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointFreeRetired(
    VOID)
{
    KIRQL oldIrql;

    for (;;)
    {
        PBREAKPOINT_INFO bp = nullptr;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        if (IsListEmpty(&g_RetiredBpList))
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            break;
        }
        bp = CONTAINING_RECORD(g_RetiredBpList.Flink, BREAKPOINT_INFO, ListEntry);
        RemoveEntryList(&bp->ListEntry);
        if (NpBpIsSingleStepOwned(bp))
        {
            // 仍被某 CPU 的单步引用：放回链尾等下一轮，避免 UAF。
            InsertTailList(&g_RetiredBpList, &bp->ListEntry);
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            break;                              // 链首在用，本轮到此为止
        }
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        ExFreePoolWithTag(bp, NP_BP_POOL_TAG);
    }

    //
    // 回收退休的断点页记录。
    //
    for (;;)
    {
        PBREAKPOINT_PAGE page = nullptr;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        if (IsListEmpty(&g_RetiredBpPageList))
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            break;
        }
        page = CONTAINING_RECORD(g_RetiredBpPageList.Flink, BREAKPOINT_PAGE,
                                 ListEntry);
        RemoveEntryList(&page->ListEntry);
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        NpBpPageFreeResources(page);        // 用户页：解锁并回收 MDL
    }
    return STATUS_SUCCESS;
}

// 按目标进程摘除全部用户态断点（进程退出/调试器分离时调用，释放 MDL，
// 避免 0x76 PROCESS_HAS_LOCKED_PAGES）。
static
NTSTATUS
NpBreakPointUninstallByProcess(
    _In_ PEPROCESS Process)
{
    ULONG ids[64];
    ULONG monIds[64];
    ULONG count = 0;
    ULONG monCount = 0;
    KIRQL oldIrql;

    if (Process == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (PLIST_ENTRY e = g_BpListHead.Flink;
         e != &g_BpListHead && count < ARRAYSIZE(ids);
         e = e->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(e, BREAKPOINT_INFO, ListEntry);
        if (bp->Active && bp->OwnerProcess == Process)
        {
            ids[count++] = bp->BpId;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (PLIST_ENTRY e = g_MonitorListHead.Flink;
         e != &g_MonitorListHead && monCount < ARRAYSIZE(monIds);
         e = e->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
        if (mon->Active && mon->OwnerProcess == Process)
        {
            monIds[monCount++] = mon->MonitorId;
        }
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    for (ULONG i = 0; i < count; i++)
    {
        NpBreakPointUninstall(ids[i], TRUE);
    }
    for (ULONG i = 0; i < monCount; i++)
    {
        NpBreakPointUninstallMonitor(monIds[i], TRUE);
    }
    return STATUS_SUCCESS;
}

static
VOID
NpBreakPointProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);
    if (CreateInfo == nullptr)
    {
        // 进程退出：摘除其用户态断点并解锁 MDL。
        NpBreakPointUninstallByProcess(Process);
    }
}

// 摘除指定进程的 PEB 影子监视（hide 关闭/解保护时调用）。
static
NTSTATUS
NpBreakPointUninstallPebShadowByProcess(
    _In_ PEPROCESS Process)
{
    ULONG ids[8];
    ULONG count = 0;
    KIRQL oldIrql;

    if (Process == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (PLIST_ENTRY e = g_MonitorListHead.Flink;
         e != &g_MonitorListHead && count < ARRAYSIZE(ids);
         e = e->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
        if (mon->Active && mon->IsPebShadow &&
            mon->OwnerProcess == Process)
        {
            ids[count++] = mon->MonitorId;
        }
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    for (ULONG i = 0; i < count; i++)
    {
        NpBreakPointUninstallMonitor(ids[i], TRUE);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointUninstallPebShadowByPid(
    ULONG ProcessId)
{
    PEPROCESS process = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId(ULongToHandle(ProcessId),
                                             &process);
    if (!NT_SUCCESS(st) || process == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    st = NpBreakPointUninstallPebShadowByProcess(process);
    ObDereferenceObject(process);
    return st;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointUninstallByPid(
    ULONG ProcessId)
{
    PEPROCESS process = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId(ULongToHandle(ProcessId),
                                             &process);
    if (!NT_SUCCESS(st) || process == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    st = NpBreakPointUninstallByProcess(process);
    ObDereferenceObject(process);
    return st;
}

//
// ==================== 进程退出通知：legacy 兜底 ====================
//

// 按 PID 摘除全部断点——不需要 EPROCESS 引用。
// legacy 进程通知回调只给 PID、不给 PEPROCESS，且此时
// PsLookupProcessByProcessId 可能已经失败（进程正在删除），所以直接拿断点
// 持有的 OwnerProcess 反查 PID 做比较。
static
NTSTATUS
NpBreakPointUninstallByPidNoRef(
    _In_ ULONG ProcessId)
{
    ULONG ids[64];
    ULONG monIds[64];
    ULONG count = 0;
    ULONG monCount = 0;
    KIRQL oldIrql;

    if (ProcessId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 断点（页记录持 MDL + 进程引用）。
    //
    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (PLIST_ENTRY e = g_BpListHead.Flink;
         e != &g_BpListHead && count < ARRAYSIZE(ids);
         e = e->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(e, BREAKPOINT_INFO, ListEntry);
        if (bp->Active && bp->OwnerProcess != nullptr &&
            HandleToULong(PsGetProcessId(bp->OwnerProcess)) == ProcessId)
        {
            ids[count++] = bp->BpId;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    //
    // 监视（PEB 影子监视持进程引用）：与 Ex 路径
    // （NpBreakPointUninstallByProcess）的清理范围保持一致。
    // 不清的话进程退出后最后一份进程引用卡在我们手里，要等 500ms
    // 清扫线程才放，进程对象延迟释放。
    //
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (PLIST_ENTRY e = g_MonitorListHead.Flink;
         e != &g_MonitorListHead && monCount < ARRAYSIZE(monIds);
         e = e->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
        if (mon->Active && mon->OwnerProcess != nullptr &&
            HandleToULong(PsGetProcessId(
                static_cast<PEPROCESS>(mon->OwnerProcess))) == ProcessId)
        {
            monIds[monCount++] = mon->MonitorId;
        }
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    for (ULONG i = 0; i < count; i++)
    {
        NpBreakPointUninstall(ids[i], TRUE);
    }
    for (ULONG i = 0; i < monCount; i++)
    {
        NpBreakPointUninstallMonitor(monIds[i], TRUE);
    }
    if (count != 0 || monCount != 0)
    {
        NpHvLogPrint("[bp] process exit pid=%lu -> removed %lu bp(s) "
                     "%lu monitor(s)\n",
                     ProcessId, count, monCount);
    }
    return STATUS_SUCCESS;
}

//
// Legacy 进程通知兜底。
//
// PsSetCreateProcessNotifyRoutineEx 内部要过 MmVerifyCallbackFunction——校验
// 回调所属驱动映像的签名/完整性，未签名（或绕过 DSE 加载）的驱动上恒返回
// 0xc0000022。legacy 版 PsSetCreateProcessNotifyRoutine 不做该校验，因此
// 作为兜底注册：只要它成功，进程退出就能立刻摘除断点并解锁 MDL，不必完全
// 依赖 500ms 清扫线程（0x76 风险显著下降）。
//
// 代价：回调签名只有 (ParentId, ProcessId, Create)，没有 PEPROCESS，
// 所以走上面的按 PID 匹配路径。
//
static
VOID
NpBreakPointProcessNotifyLegacy(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (Create)
    {
        return;
    }
    NpBreakPointUninstallByPidNoRef(HandleToULong(ProcessId));
}

// 轮询兜底：进程退出通知注册失败（0xc0000022）时，周期性检查用户态
// 断点所属进程是否已退出（KPROCESS 是派发对象，退出时置信号态），
// 自动摘除断点并解锁 MDL，避免 0x76 PROCESS_HAS_LOCKED_PAGES。
static
VOID
NpBreakPointSweepThread(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER interval;
    interval.QuadPart = -10000LL * 500;     // 500ms

    for (;;)
    {
        struct
        {
            ULONG BpId;
            PKPROCESS Process;
        } candidates[64];
        ULONG count = 0;
        KIRQL oldIrql;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        for (PLIST_ENTRY e = g_BpListHead.Flink;
             e != &g_BpListHead && count < ARRAYSIZE(candidates);
             e = e->Flink)
        {
            PBREAKPOINT_INFO bp = CONTAINING_RECORD(e, BREAKPOINT_INFO,
                                                    ListEntry);
            if (bp->Active && bp->OwnerProcess != nullptr)
            {
                candidates[count].BpId = bp->BpId;
                candidates[count].Process =
                    reinterpret_cast<PKPROCESS>(bp->OwnerProcess);
                count++;
            }
        }
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        struct
        {
            ULONG MonitorId;
            PKPROCESS Process;
        } monCandidates[64];
        ULONG monCount = 0;

        KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
        for (PLIST_ENTRY e = g_MonitorListHead.Flink;
             e != &g_MonitorListHead && monCount < ARRAYSIZE(monCandidates);
             e = e->Flink)
        {
            PMONITOR_INFO mon = CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
            if (mon->Active && mon->OwnerProcess != nullptr)
            {
                monCandidates[monCount].MonitorId = mon->MonitorId;
                monCandidates[monCount].Process =
                    reinterpret_cast<PKPROCESS>(mon->OwnerProcess);
                monCount++;
            }
        }
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        for (ULONG i = 0; i < count; i++)
        {
            if (KeWaitForSingleObject(candidates[i].Process, Executive,
                                      KernelMode, FALSE, &zero) ==
                STATUS_SUCCESS)
            {
                NpBreakPointUninstall(candidates[i].BpId, TRUE);
            }
        }
        for (ULONG i = 0; i < monCount; i++)
        {
            if (KeWaitForSingleObject(monCandidates[i].Process, Executive,
                                      KernelMode, FALSE, &zero) ==
                STATUS_SUCCESS)
            {
                NpBreakPointUninstallMonitor(monCandidates[i].MonitorId, TRUE);
            }
        }

        // 清理待删除断点：continue 的 re-CC 会清 DeletePending；残留即删除。
        for (;;)
        {
            ULONG delId = 0;
            KeAcquireSpinLock(&g_BpListLock, &oldIrql);
            for (PLIST_ENTRY e = g_BpListHead.Flink;
                 e != &g_BpListHead;
                 e = e->Flink)
            {
                PBREAKPOINT_INFO bp = CONTAINING_RECORD(e, BREAKPOINT_INFO,
                                                        ListEntry);
                if (bp->DeletePending)
                {
                    delId = bp->BpId;
                    break;
                }
            }
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            if (delId == 0)
            {
                break;
            }
            NpBreakPointUninstall(delId, TRUE);
        }

        //
        // 回收 VMEXIT 上下文摘除的断点结构（删除确认/单次断点挂进来的）。
        //
        NpBreakPointFreeRetired();

        KeWaitForSingleObject(&g_BpSweepEvent, Executive, KernelMode, FALSE,
                              &interval);
        if (g_BpSweepExit)
        {
            break;
        }
    }
    g_BpSweepExited = TRUE;
    PsTerminateSystemThread(STATUS_SUCCESS);
}

_Use_decl_annotations_
ULONG
NpBreakPointGetActiveCount(
    VOID)
{
    PLIST_ENTRY entry;
    ULONG count;
    KIRQL oldIrql;

    count = 0;
    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (entry = g_BpListHead.Flink;
         entry != &g_BpListHead;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (bp->Active)
        {
            count++;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    return count;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointQuery(
    PNPHV_BREAKPOINT_INFO_ENTRY Entries,
    ULONG MaxCount,
    PULONG OutCount)
{
    PLIST_ENTRY entry;
    ULONG count;
    KIRQL oldIrql;

    if (Entries == nullptr || OutCount == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *OutCount = 0;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    count = 0;
    for (entry = g_BpListHead.Flink;
         entry != &g_BpListHead && count < MaxCount;
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (!bp->Active)
        {
            continue;
        }
        Entries[count].BpId = bp->BpId;
        Entries[count].Flags = bp->Flags;
        Entries[count].Active = 1;
        Entries[count].Halted = bp->Halted ? 1 : 0;
        Entries[count].Address = bp->Address;
        Entries[count].HitCount = bp->HitCount;
        Entries[count].LastHitCr3 = bp->LastHitCr3;
        Entries[count].LastHitRip = bp->LastHitRip;
        Entries[count].LastHitCpu = bp->LastHitCpu;
        Entries[count].Reserved = 0;
        count++;
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    *OutCount = count;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
NpBreakPointIsPageOccupied(
    ULONG_PTR PageGpa)
{
    KIRQL oldIrql;
    BOOLEAN occupied;

    occupied = FALSE;
    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    if (NpFindBreakpointByPage(PageGpa) != nullptr)
    {
        occupied = TRUE;
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    return occupied;
}

_Use_decl_annotations_
BOOLEAN
NpBreakPointIsHaltedPage(
    ULONG_PTR PageGpa)
{
    KIRQL oldIrql;
    BOOLEAN halted = FALSE;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    //
    // 按页判断：同页多断点时链表首个断点未必是被 HALT 钉住的那个，
    // 只查首个会漏判，看门狗会把合法的忙循环误报成 0xDEAD0001。
    //
    PBREAKPOINT_PAGE page = NpFindPageByGpa(PageGpa);
    if (page != nullptr && NpBpPageFindHalted(page) != nullptr)
    {
        halted = TRUE;
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    return halted;
}

//
// ============================ 继续（HALT 模式） ============================
//

static
NTSTATUS
NpContinueOnCpu(
    _In_ PBREAKPOINT_INFO Bp
    )
{
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;
    NTSTATUS status;

    status = KeGetProcessorNumberFromIndex(Bp->HaltCpu, &processorNumber);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    affinity.Group = processorNumber.Group;
    affinity.Mask = 1ULL << processorNumber.Number;
    affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
    KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

    //
    // 在断点暂停所在 CPU 上执行 vmmcall：VMM 在自己的 VMEXIT 上下文
    // 修改 VMCB（RFLAGS.TF）与 NPT 叶子——避免跨 CPU 修改活动 VMCB
    // 的竞态。
    //
    AsmVmmCallBpContinue(Bp->BpId);

    KeRevertToUserGroupAffinityThread(&oldAffinity);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointContinue(
    ULONG BpId)
{
    KIRQL oldIrql;

    if (BpId != 0)
    {
        PBREAKPOINT_INFO bp;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        bp = NpFindBreakpointById(BpId);
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        if (bp == nullptr || !bp->Active || !bp->Halted)
        {
            return STATUS_NOT_FOUND;
        }
        return NpContinueOnCpu(bp);
    }

    //
    // BpId=0：收集全部被暂停的断点，逐个在各自 CPU 上继续。
    //
    PBREAKPOINT_INFO halted[64];
    ULONG count = 0;
    PLIST_ENTRY entry;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (entry = g_BpListHead.Flink;
         entry != &g_BpListHead && count < ARRAYSIZE(halted);
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (bp->Active && bp->Halted)
        {
            halted[count++] = bp;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    for (ULONG i = 0; i < count; i++)
    {
        NpContinueOnCpu(halted[i]);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
NpBreakPointTryDeleteDebuggerBp(
    ULONG_PTR Address,
    UCHAR OriginalByte,
    BOOLEAN ExternalWriter,
    ULONG Length)
{
    PBREAKPOINT_INFO bp = nullptr;
    KIRQL oldIrql;
    ULONG bpId = 0;
    BOOLEAN removed = FALSE;
    BOOLEAN found = FALSE;
    BOOLEAN wasPaused = FALSE;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointByAddress(Address);
    if (bp != nullptr && bp->Active &&
        (bp->Flags & NPHV_BP_FLAG_DEBUGGER) && ExternalWriter &&
        Length == 1 && OriginalByte != 0xCC &&
        bp->ShadowPage0 != nullptr &&
        *((PUCHAR)bp->ShadowPage0 + bp->PageOffset) == OriginalByte)
    {
        found = TRUE;
        wasPaused = bp->DebuggerPaused ? TRUE : FALSE;
        bp->StepOverSeen = TRUE;    // 调试器仍在按 step-over 流程对待它
        if (!bp->DebuggerPaused)
        {
            bpId = bp->BpId;            // 运行中恢复原字节 = 删除：确定
        }
        else
        {
            // 暂停中写回原字节可能是 continue 恢复步，也可能真是删除。
            // 不卸载（避免 churn）：只标记待删除，continue 的 re-CC 会
            // 清 DeletePending；真删除由清扫/下次命中确认并停用。
            bp->DeletePending = TRUE;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    static volatile LONG s_delDiag = 0;
    if (InterlockedIncrement((volatile LONG *)&s_delDiag) <= 48)
    {
        NpHvLogPrint("[bp] try-delete addr=%p byte=%02X found=%u paused=%u "
                     "remove=%u\n",
                     (PVOID)Address, OriginalByte,
                     found ? 1 : 0, wasPaused ? 1 : 0,
                     bpId != 0 ? 1 : 0);
    }

    if (bpId != 0)
    {
        NpBreakPointUninstall(bpId, TRUE);
        NpHvLogPrint("[bp] debugger delete @0x%p -> NPT breakpoint removed\n",
                     reinterpret_cast<PVOID>(Address));
        removed = TRUE;
    }
    return removed;
}

/*!
    @brief      调试器 continue 时清扫"僵尸断点"。

    @details    背景：x64dbg 删除断点时**不一定写内存**——
                `cbDebugDeleteBPX` 里是 `if(found.enabled && !DeleteBPX(...))`，
                只有内部 enabled 为真才调 DeleteBPX（写回原字节）。continue
                之后再删除的实测结果是：对断点地址**既没有 0x48 也没有 0xCC
                的写**，驱动侧的 try-delete 完全收不到信号，断点永久残留，
                再运行目标函数仍被断下。

                区分依据（实测日志证实的稳定行为差异）：
                - 调试器**仍认**这个断点 → 恢复前必然走 step-over：先把原
                  字节写回（try-delete 命中 → StepOverSeen=TRUE），单步，
                  再重写 0xCC（ReArmByAddress 清 DebuggerPaused）；
                - 调试器**已不认**它（断点已删除）→ 收到的是未预期的
                  #BP，continue 时**没有任何 step-over 准备动作**，
                  DebuggerPaused 会一直挂着。

                因此：continue 到来时，仍处于 DebuggerPaused 且本轮
                StepOverSeen 为假的断点，判定为僵尸并摘除。

    @param[in]  TargetPid   被调试进程 PID；**0 = 不过滤，扫描全部 DEBUGGER
                            断点**。真实附加（passthrough）模式下 pseudo 会话
                            不存在，`NtDebugContinue` 的 Arg1 是调试对象句柄
                            而非进程句柄，target 解析恒为 0——此时必须走
                            "不过滤"分支，否则清扫永不触发。
*/
_Use_decl_annotations_
VOID
NpBreakPointReapZombieOnContinue(
    ULONG TargetPid)
{
    ULONG ids[32];
    ULONG count = 0;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (PLIST_ENTRY e = g_BpListHead.Flink;
         e != &g_BpListHead && count < ARRAYSIZE(ids);
         e = e->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(e, BREAKPOINT_INFO,
                                                ListEntry);
        if (!bp->Active || !(bp->Flags & NPHV_BP_FLAG_DEBUGGER) ||
            bp->OwnerProcess == nullptr)
        {
            continue;
        }
        if (TargetPid != 0 && HandleToULong(PsGetProcessId(
                static_cast<PEPROCESS>(bp->OwnerProcess))) != TargetPid)
        {
            continue;
        }
        if (bp->DebuggerPaused &&
            (bp->DeletePending || !bp->StepOverSeen))
        {
            ids[count++] = bp->BpId;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    for (ULONG i = 0; i < count; i++)
    {
        NpHvLogPrint("[bp] zombie reaped id=%u pid=%lu (debugger no longer "
                     "owns it: no step-over before continue)\n",
                     ids[i], TargetPid);
        NpBreakPointUninstall(ids[i], TRUE);
    }
}

_Use_decl_annotations_
BOOLEAN
NpBreakPointIsDebuggerBpAt(
    ULONG_PTR Address)
{
    PBREAKPOINT_INFO bp = nullptr;
    KIRQL oldIrql;
    BOOLEAN hit = FALSE;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointByAddress(Address);
    if (bp != nullptr && bp->Active &&
        (bp->Flags & NPHV_BP_FLAG_DEBUGGER))
    {
        hit = TRUE;
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    return hit;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointRefreshShadowOnPatch(
    ULONG_PTR Address,
    PEPROCESS Process,
    PVOID UserBuffer,
    ULONG Length)
{
    PBREAKPOINT_INFO bp = nullptr;
    PBREAKPOINT_PAGE page = nullptr;
    KIRQL oldIrql;
    ULONG bpId = 0;
    UCHAR patchBuf[64];
    KAPC_STATE apcState;

    if (Process == nullptr || UserBuffer == nullptr || Length == 0 ||
        Length > sizeof(patchBuf))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(NpMemAccessCopyFromUser(
            reinterpret_cast<ULONG_PTR>(UserBuffer), patchBuf, Length)))
    {
        return STATUS_ACCESS_VIOLATION;
    }

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointByAddress(Address);
    if (bp != nullptr && bp->Active &&
        (bp->Flags & NPHV_BP_FLAG_DEBUGGER) &&
        bp->OwnerProcess == Process &&
        bp->ShadowPage0 != nullptr && bp->ShadowPage1 != nullptr)
    {
        bpId = bp->BpId;
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    if (bpId == 0)
    {
        return STATUS_NOT_FOUND;
    }

    // 补丁写进真实页，再整页刷新影子（执行/读取视图同步为补丁后内容）。
    KeStackAttachProcess(Process, &apcState);
    __try
    {
        PUCHAR pageVa = reinterpret_cast<PUCHAR>(PAGE_ALIGN_DOWN(Address));
        RtlCopyMemory(pageVa + (Address & 0xFFF), patchBuf, Length);
        RtlCopyMemory(bp->ShadowPage0, pageVa, PAGE_SIZE);
        RtlCopyMemory(bp->ShadowPage1, pageVa, PAGE_SIZE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KeUnstackDetachProcess(&apcState);
        return STATUS_ACCESS_VIOLATION;
    }
    KeUnstackDetachProcess(&apcState);

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointById(bpId);
    page = (bp != nullptr) ? bp->Page : nullptr;
    if (page != nullptr)
    {
        //
        // 重建 CC 副本：整页重拷后按该页全部断点偏移重打 0xCC。不能只补本
        // 断点的 INT3——那会把同页其它断点的 CC 用补丁字节覆盖掉。
        //
        NpBpPageRebuildCc(page);
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);
    if (page == nullptr || bp == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    // 全 CPU 重新武装（ASID 刷新）+ 跨核缓存失效：影子字节变了，必须让
    // 其它核的指令/数据缓存视图同步，否则仍会执行旧的影子内容。
    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = bp;
    cpuContext.Monitor = nullptr;
    cpuContext.CpuIndex = 0;
    NpBreakPointExecuteOnEachProcessor(NpBreakPointConfigureOnProcessor,
                                       &cpuContext);
    NpBpInvalidateShadowCaches(page);
    NpHvLogPrint("[bp] patch refresh addr=%p len=%u bps-on-page=%lu\n",
                 (PVOID)Address, Length, page->RefCount);
    return STATUS_SUCCESS;
}

/*!
    @brief      重新武装 DEBUGGER 模式断点（调试器恢复断点时调用）。
    @details    清除 DebuggerPaused 并在全部 CPU 恢复影子页0 NX=1。
                由 NpDebugHide 的 NtWriteVirtualMemory 回调（调试器重写
                0xCC）触发；只处理 DEBUGGER 且暂停中的断点。
 */
_Use_decl_annotations_
VOID
NpBreakPointReArmByAddress(
    ULONG_PTR Address)
{
    PBREAKPOINT_INFO bp = nullptr;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    bp = NpFindBreakpointByAddress(Address);
    if (bp == nullptr || !bp->Active ||
        !(bp->Flags & NPHV_BP_FLAG_DEBUGGER) || !bp->DebuggerPaused)
    {
        KeReleaseSpinLock(&g_BpListLock, oldIrql);
        return;
    }
    bp->DebuggerPaused = FALSE;
    bp->DebuggerPausedCount = 0;
    bp->DeletePending = FALSE;
    bp->StepOverSeen = FALSE;   // 一轮完整的 step-over（写原字节→单步→重装）结束
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    static volatile LONG s_rearmDiag = 0;
    if (InterlockedIncrement((volatile LONG *)&s_rearmDiag) <= 32)
    {
        NpHvLogPrint("[bp] rearm addr=%p\n", (PVOID)Address);
    }

    //
    // 全部 CPU 恢复影子页0 NX=1（重新武装）。
    //
    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = bp;
    cpuContext.Monitor = nullptr;
    cpuContext.CpuIndex = 0;
    NpBreakPointExecuteOnEachProcessor(NpBreakPointConfigureOnProcessor,
                                       &cpuContext);
}

//
// ============================ DR 探测：开关 / 查询 ============================
//

_Use_decl_annotations_
NTSTATUS
NpBreakPointSetDrProbe(
    BOOLEAN Enable)
{
    ULONG numProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;
    NTSTATUS status;

    if (NpHvIsRunning() == FALSE)
    {
        return STATUS_NOT_SUPPORTED;
    }

    numProcessors = NpHvGetProcessorCount();
    for (ULONG i = 0; i < numProcessors; i++)
    {
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        //
        // 逐 CPU 在自己的 VMEXIT 上下文切换 VMCB 拦截位（跨核改 VMCB 有竞态）。
        //
        AsmVmmCallDrProbe(Enable ? 1 : 0);

        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }

    NpHvLogPrint("[dr] drprobe %s\n", Enable ? "enabled" : "disabled");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointQueryDrState(
    PNPHV_DRSTATE_RESPONSE Response)
{
    PVIRTUAL_PROCESSOR_DATA vpData = nullptr;
    PNP_BP_CPU_STATE cpuState;
    ULONG outCount = 0;

    if (Response == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(NPHV_DRSTATE_RESPONSE));

    //
    // 聚合所有 CPU 的假 DR 状态：线程可能在任意核写入 DR，
    // 单查 CPU0 会漏掉迁移后写入的断点。合并各核 Pending 列表
    // （同地址去重），DrProbeEnabled 取任一核。
    //
    for (ULONG i = 0; i < NpHvGetProcessorCount(); i++)
    {
        if (!NT_SUCCESS(NpHvGetProcessorData(i, &vpData)) || vpData == nullptr)
        {
            continue;
        }
        cpuState = static_cast<PNP_BP_CPU_STATE>(vpData->ServiceData);
        if (cpuState == nullptr)
        {
            continue;
        }

        if (cpuState->DrProbeEnabled)
        {
            Response->DrProbeEnabled = 1;
        }
        //
        // 假 DR 值：非零（有断点）的核优先覆盖（最后写入者）。
        //
        if (cpuState->FakeDr0 != 0) Response->Dr0 = cpuState->FakeDr0;
        if (cpuState->FakeDr1 != 0) Response->Dr1 = cpuState->FakeDr1;
        if (cpuState->FakeDr2 != 0) Response->Dr2 = cpuState->FakeDr2;
        if (cpuState->FakeDr3 != 0) Response->Dr3 = cpuState->FakeDr3;
        if (cpuState->FakeDr6 != 0) Response->Dr6 = cpuState->FakeDr6;
        if (cpuState->FakeDr7 != 0) Response->Dr7 = cpuState->FakeDr7;

        //
        // 合并 Pending（去重：同地址同类型只保留一个）。
        //
        for (ULONG p = 0; p < cpuState->PendingCount && outCount < 4; p++)
        {
            BOOLEAN dup = FALSE;
            for (ULONG q = 0; q < outCount; q++)
            {
                if (Response->PendingAddresses[q] ==
                        cpuState->PendingAddresses[p] &&
                    Response->PendingTypes[q] == cpuState->PendingTypes[p])
                {
                    dup = TRUE;
                    break;
                }
            }
            if (!dup)
            {
                Response->PendingAddresses[outCount] =
                    cpuState->PendingAddresses[p];
                Response->PendingTypes[outCount] =
                    cpuState->PendingTypes[p];
                outCount++;
            }
        }
    }

    if (outCount == 0 && Response->DrProbeEnabled == 0)
    {
        //
        // 没有核有状态（服务未初始化）：仍返回成功（空状态）。
        //
    }
    Response->PendingCount = outCount;
    Response->Status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

//
// ============================ 监视安装 / 卸载 ============================
//

_Use_decl_annotations_
NTSTATUS
NpBreakPointInstallMonitor(
    ULONG_PTR Address,
    ULONG AccessType,
    PULONG OutMonitorId)
{
    PMONITOR_INFO mon;
    NTSTATUS status;
    ULONG_PTR originalPhysical;
    KIRQL oldIrql;

    if (OutMonitorId == nullptr || Address == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *OutMonitorId = 0;

    if ((AccessType & (NPHV_MON_ACCESS_READ | NPHV_MON_ACCESS_WRITE)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Address < 0xFFFF800000000000ULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    originalPhysical = MmGetPhysicalAddress(
        reinterpret_cast<PVOID>(PAGE_ALIGN_DOWN(Address))).QuadPart;
    if (originalPhysical == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 同页互斥：Hook / 断点 / 监视。
    //
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    BOOLEAN monOccupied = (NpFindMonitorByPage(originalPhysical) != nullptr);
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    if (monOccupied || NpHookIsPageHooked(originalPhysical) ||
        NpBreakPointIsPageOccupied(originalPhysical))
    {
        return STATUS_ALREADY_REGISTERED;
    }

    mon = static_cast<PMONITOR_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                     sizeof(MONITOR_INFO),
                                                     NP_BP_POOL_TAG));
    if (mon == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(mon, sizeof(MONITOR_INFO));

    mon->Address = Address;
    mon->PageGpa = originalPhysical;
    mon->AccessType = AccessType;

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    mon->MonitorId = g_NextMonitorId++;
    mon->Active = TRUE;
    InsertTailList(&g_MonitorListHead, &mon->ListEntry);
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = nullptr;
    cpuContext.Monitor = mon;
    cpuContext.CpuIndex = 0;

    status = NpBreakPointExecuteOnEachProcessor(
                NpBreakPointMonitorConfigureOnProcessor,
                &cpuContext);
    if (!NT_SUCCESS(status))
    {
        NpBreakPointUninstallMonitor(mon->MonitorId, FALSE);
        return status;
    }

    *OutMonitorId = mon->MonitorId;
    NpHvLogPrint("[mon] install id=%u addr=0x%p pa=0x%llx access=0x%x\n",
                 mon->MonitorId,
                 reinterpret_cast<PVOID>(Address),
                 originalPhysical,
                 AccessType);
    return STATUS_SUCCESS;
}

// PEB 影子监视：把目标进程 PEB 页经 NPT 重定向到干净副本。OS 附加时写
// 真实 PEB 页（BeingDebugged=1），写陷阱命中后由 #DB 同步影子页并强制
// 清掉调试字段；Guest/调试器/物理直读看到的都是干净副本。
_Use_decl_annotations_
NTSTATUS
NpBreakPointInstallPebShadow(
    _In_ PEPROCESS Process,
    _Out_ PULONG OutMonitorId)
{
    PMONITOR_INFO mon = nullptr;
    NTSTATUS status;
    KIRQL oldIrql;
    PVOID peb = nullptr;
    PVOID pageVa = nullptr;
    PVOID shadow = nullptr;
    ULONG_PTR shadowPa = 0;
    ULONG_PTR realPa = 0;
        KAPC_STATE apcState;
    BOOLEAN attached = FALSE;

    if (Process == nullptr || OutMonitorId == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *OutMonitorId = 0;

    peb = PsGetProcessPeb(Process);
    if (peb == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    pageVa = reinterpret_cast<PVOID>(PAGE_ALIGN_DOWN(
        reinterpret_cast<ULONG_PTR>(peb)));

    KeStackAttachProcess(Process, &apcState);
    attached = TRUE;

    __try
    {
        ProbeForRead(pageVa, PAGE_SIZE, 1);
        realPa = MmGetPhysicalAddress(pageVa).QuadPart;
        if (realPa == 0)
        {
            status = STATUS_NOT_FOUND;
            goto Exit;
        }

        // 不持锁 MDL：进程退出时 notify 不可用，锁页会触发 0x76。
        shadow = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE,
                                 NP_BP_POOL_TAG);
        if (shadow == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        shadowPa = MmGetPhysicalAddress(shadow).QuadPart;
        if (shadowPa == 0)
        {
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        MM_COPY_ADDRESS src;
        SIZE_T transferred = 0;
        src.PhysicalAddress.QuadPart = static_cast<LONGLONG>(realPa);
        if (!NT_SUCCESS(MmCopyMemory(shadow, src, PAGE_SIZE,
                                     MM_COPY_MEMORY_PHYSICAL,
                                     &transferred)) ||
            transferred != PAGE_SIZE)
        {
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }
        *(volatile UCHAR *)((PUCHAR)shadow + 0x02) = 0;         // BeingDebugged
        *(volatile ULONG *)((PUCHAR)shadow + 0xBC) &= ~0x70UL;  // NtGlobalFlag heap flags
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        if (NT_SUCCESS(status))
        {
            status = STATUS_ACCESS_VIOLATION;
        }
    }

Exit:
    if (attached)
    {
        KeUnstackDetachProcess(&apcState);
        attached = FALSE;
    }
    if (!NT_SUCCESS(status))
    {
        if (shadow != nullptr)
        {
            ExFreePoolWithTag(shadow, NP_BP_POOL_TAG);
        }
        return status;
    }

    // 同页互斥：Hook / 断点 / 监视 只能占用其一。
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    BOOLEAN occupied = (NpFindMonitorByPage(realPa) != nullptr);
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    if (occupied || NpHookIsPageHooked(realPa) ||
        NpBreakPointIsPageOccupied(realPa))
    {
        status = STATUS_ALREADY_REGISTERED;
        goto ExitCleanup;
    }

    mon = static_cast<PMONITOR_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                     sizeof(MONITOR_INFO),
                                                     NP_BP_POOL_TAG));
    if (mon == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitCleanup;
    }
    RtlZeroMemory(mon, sizeof(MONITOR_INFO));

    mon->Address = reinterpret_cast<ULONG_PTR>(peb);
    mon->PageGpa = realPa;
    mon->AccessType = NPHV_MON_ACCESS_WRITE;
    mon->IsPebShadow = TRUE;
    mon->IsLdrShadow = FALSE;
    ObReferenceObject(Process);
    mon->OwnerProcess = Process;
    mon->ShadowPage = shadow;
    mon->ShadowPagePA = shadowPa;

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    mon->MonitorId = g_NextMonitorId++;
    mon->Active = TRUE;
    InsertTailList(&g_MonitorListHead, &mon->ListEntry);
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = nullptr;
    cpuContext.Monitor = mon;
    cpuContext.CpuIndex = 0;
    status = NpBreakPointExecuteOnEachProcessor(
                NpBreakPointMonitorConfigureOnProcessor,
                &cpuContext);
    if (!NT_SUCCESS(status))
    {
        NpBreakPointUninstallMonitor(mon->MonitorId, FALSE);
        return status;
    }

    *OutMonitorId = mon->MonitorId;
    NpHvLogPrint("[mon] peb-shadow install pid=%lu peb=0x%p pa=0x%llx "
                 "shadow=0x%llx\n",
                 static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                     PsGetProcessId(Process))),
                 peb,
                 realPa,
                 shadowPa);
    return STATUS_SUCCESS;

ExitCleanup:
    if (shadow != nullptr)
    {
        ExFreePoolWithTag(shadow, NP_BP_POOL_TAG);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS
NpBreakPointUninstallMonitor(
    ULONG MonitorId,
    BOOLEAN FreeResources)
{
    PMONITOR_INFO mon = nullptr;
    KIRQL oldIrql;

    BOOLEAN inUse = FALSE;

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    mon = NpFindMonitorById(MonitorId);
    if (mon == nullptr || !mon->Active)
    {
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
        return STATUS_NOT_FOUND;
    }
    mon->Active = FALSE;
    RemoveEntryList(&mon->ListEntry);

    //
    // 单步占用检查与摘除同锁（#DB handler 在同一把 g_MonitorListLock 内
    // 清 SingleStepOwner）——防"扫描不在用→释放"与"单步中引用"竞态。
    //
    inUse = NpBpIsSingleStepOwned(mon);
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    BP_CPU_CONTEXT cpuContext;
    cpuContext.Bp = nullptr;
    cpuContext.Monitor = mon;
    cpuContext.CpuIndex = 0;
    NpBreakPointExecuteOnEachProcessor(NpBreakPointMonitorRestoreOnProcessor,
                                       &cpuContext);

    if (FreeResources != FALSE)
    {
        if (!inUse)
        {
            NpMonFinalRelease(mon);
            ExFreePoolWithTag(mon, NP_BP_POOL_TAG);
        }
        else
        {
            NpHvLogPrint("[bp] uninstall monitor id=%u deferred (single-step "
                         "in progress)\n", MonitorId);
            KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
            InsertTailList(&g_RetiredMonitorList, &mon->ListEntry);
            KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
        }
    }
    else
    {
        KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
        InsertTailList(&g_RetiredMonitorList, &mon->ListEntry);
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    }
    return STATUS_SUCCESS;
}

// 物理直读路径：命中 PEB 影子监视时返回影子页物理地址（读干净副本）。
// 任意 IRQL 可调（自旋锁保护）。
_Use_decl_annotations_


static NTSTATUS NpInstallShadowForGpa(ULONG_PTR gpa, ULONG off, PLIST_ENTRY newFlink, PLIST_ENTRY newBlink, BOOLEAN patchFlink, BOOLEAN patchBlink){
    // Check already has shadow for this GPA
    KIRQL irql; KeAcquireSpinLock(&g_MonitorListLock, &irql);
    for(PLIST_ENTRY e=g_MonitorListHead.Flink; e!=&g_MonitorListHead; e=e->Flink){
        PMONITOR_INFO m=CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
        if(m->Active && m->IsLdrShadow && m->PageGpa==(gpa & ~(PAGE_SIZE-1))){ KeReleaseSpinLock(&g_MonitorListLock, irql); return STATUS_SUCCESS; }
    }
    KeReleaseSpinLock(&g_MonitorListLock, irql);
    PVOID sh = NpAllocateContiguousPage();
    if(!sh) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(sh, PAGE_SIZE);
    ULONG_PTR shPa = MmGetPhysicalAddress(sh).QuadPart;
    if(!shPa){ MmFreeContiguousMemory(sh); return STATUS_UNSUCCESSFUL; }
    SIZE_T tr=0; MM_COPY_ADDRESS src; src.PhysicalAddress.QuadPart=(LONGLONG)(gpa & ~(PAGE_SIZE-1));
    if(!NT_SUCCESS(MmCopyMemory(sh, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &tr)) || tr!=PAGE_SIZE){ MmFreeContiguousMemory(sh); return STATUS_UNSUCCESSFUL; }
    if(off != (ULONG_PTR)-1){
        PLIST_ENTRY e = (PLIST_ENTRY)((PUCHAR)sh + off);
        if(patchFlink) e->Flink = newFlink;
        if(patchBlink) e->Blink = newBlink;
    }
    PMONITOR_INFO mon=(PMONITOR_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MONITOR_INFO), NP_BP_POOL_TAG);
    if(!mon){ MmFreeContiguousMemory(sh); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlZeroMemory(mon, sizeof(MONITOR_INFO));
    mon->PageGpa = gpa & ~(PAGE_SIZE-1);
    mon->Address = gpa + (off!=(ULONG_PTR)-1?off:0);
    mon->IsLdrShadow=TRUE; mon->IsPebShadow=FALSE; mon->ShadowPage=sh; mon->ShadowPagePA=shPa;
    KeAcquireSpinLock(&g_MonitorListLock, &irql);
    mon->MonitorId=g_NextMonitorId++; mon->Active=TRUE; InsertTailList(&g_MonitorListHead, &mon->ListEntry);
    KeReleaseSpinLock(&g_MonitorListLock, irql);
    extern VOID NpSetMonitorLeaf(PVIRTUAL_PROCESSOR_DATA, PMONITOR_INFO, BOOLEAN);
    for(ULONG i=0;i<NpHvGetProcessorCount();i++){ PVIRTUAL_PROCESSOR_DATA vp=nullptr; if(NT_SUCCESS(NpHvGetProcessorData(i,&vp))&&vp) NpSetMonitorLeaf(vp, mon, TRUE); }
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
NTSTATUS
NpBreakPointInstallLdrShadow(
    _In_ PVOID LdrEntry,
    _Out_ PULONG OutMonitorId)
{
    PMONITOR_INFO mon = nullptr;
    KIRQL oldIrql;
    PVOID pageVa = nullptr;
    PVOID shadow = nullptr;
    ULONG_PTR shadowPa = 0;
    ULONG_PTR realPa = 0;
    if (!LdrEntry || !OutMonitorId) return STATUS_INVALID_PARAMETER;
    *OutMonitorId=0;
    pageVa = (PVOID)((ULONG_PTR)LdrEntry & ~(PAGE_SIZE-1));
    realPa = MmGetPhysicalAddress(pageVa).QuadPart;
    if (!realPa) return STATUS_NOT_FOUND;
    shadow = NpAllocateContiguousPage();
    if (!shadow) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(shadow, PAGE_SIZE);
    shadowPa = MmGetPhysicalAddress(shadow).QuadPart;
    if (!shadowPa) { MmFreeContiguousMemory(shadow); return STATUS_UNSUCCESSFUL; }
    SIZE_T tr=0; MM_COPY_ADDRESS src; src.PhysicalAddress.QuadPart = (LONGLONG)realPa;
    if (!NT_SUCCESS(MmCopyMemory(shadow, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &tr)) || tr!=PAGE_SIZE) { MmFreeContiguousMemory(shadow); return STATUS_UNSUCCESSFUL; }
    {
        ULONG off = (ULONG)((ULONG_PTR)LdrEntry & (PAGE_SIZE-1));
        PLIST_ENTRY shadowEntry = (PLIST_ENTRY)((PUCHAR)shadow + off);
        PLIST_ENTRY next = shadowEntry->Flink;
        PLIST_ENTRY prev = shadowEntry->Blink;
        if (next && prev) {
            BOOLEAN inSamePage = ((ULONG_PTR)prev & ~(PAGE_SIZE-1)) == ((ULONG_PTR)pageVa & ~(PAGE_SIZE-1)) && ((ULONG_PTR)next & ~(PAGE_SIZE-1)) == ((ULONG_PTR)pageVa & ~(PAGE_SIZE-1));
            if (inSamePage) {
                PLIST_ENTRY prevInShadow = (PLIST_ENTRY)((PUCHAR)shadow + ((PUCHAR)prev - (PUCHAR)pageVa));
                PLIST_ENTRY nextInShadow = (PLIST_ENTRY)((PUCHAR)shadow + ((PUCHAR)next - (PUCHAR)pageVa));
                prevInShadow->Flink = next;
                nextInShadow->Blink = prev;
            } else {
                // Cross-page: install shadows for prev and next pages
                ULONG_PTR prevVirtPage = (ULONG_PTR)prev & ~(PAGE_SIZE-1);
                ULONG_PTR nextVirtPage = (ULONG_PTR)next & ~(PAGE_SIZE-1);
                ULONG_PTR prevPa = MmGetPhysicalAddress((PVOID)prevVirtPage).QuadPart;
                ULONG_PTR nextPa = MmGetPhysicalAddress((PVOID)nextVirtPage).QuadPart;
                ULONG prevOff = (ULONG)((ULONG_PTR)prev & (PAGE_SIZE-1));
                ULONG nextOff = (ULONG)((ULONG_PTR)next & (PAGE_SIZE-1));
                // DIRECT DKOM for neighbors: do not shadow whole page (would shadow KCB)
                // Write to real pages (no NPT shadow yet for prev/next)
                if (prevPa && prevPa != realPa) {
                    __try { prev->Flink = next; } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
                if (nextPa && nextPa != realPa && nextPa != prevPa) {
                    __try { next->Blink = prev; } __except(EXCEPTION_EXECUTE_HANDLER) {}
                } else if (nextPa && nextPa == prevPa && prevPa != realPa) {
                    // Same page for prev and next, patch both in one shadow (already installed for prev, now patch Blink)
                    // Same page for prev/next: both on same 4K page, direct DKOM already handled above
                    // If they are same page, the two writes above already did prev->Flink and next->Blink
                    // No NPT shadow needed
                    { __try { prev->Flink = next; next->Blink = prev; } __except(EXCEPTION_EXECUTE_HANDLER) {} }
                }
            }
            RtlZeroMemory(shadowEntry, sizeof(LIST_ENTRY)*3);
        }
    }
    mon = (PMONITOR_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MONITOR_INFO), NP_BP_POOL_TAG);
    if (!mon) { MmFreeContiguousMemory(shadow); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlZeroMemory(mon, sizeof(MONITOR_INFO));
    mon->PageGpa = realPa;
    mon->Address = (ULONG_PTR)LdrEntry;
    mon->IsPebShadow = FALSE; mon->IsLdrShadow = TRUE;
    mon->ShadowPage = shadow; mon->ShadowPagePA = shadowPa;
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    mon->MonitorId = g_NextMonitorId++; mon->Active = TRUE; InsertTailList(&g_MonitorListHead, &mon->ListEntry);
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    extern VOID NpSetMonitorLeaf(PVIRTUAL_PROCESSOR_DATA, PMONITOR_INFO, BOOLEAN);
    for(ULONG i=0;i<NpHvGetProcessorCount();i++){ PVIRTUAL_PROCESSOR_DATA vp=nullptr; if(NT_SUCCESS(NpHvGetProcessorData(i,&vp))&&vp) NpSetMonitorLeaf(vp, mon, TRUE); }
    *OutMonitorId = mon->MonitorId;
    return STATUS_SUCCESS;
}

BOOLEAN
NpBreakPointGetPebShadowPa(
    ULONG_PTR PageGpa,
    PULONG_PTR OutShadowPa)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (OutShadowPa == nullptr)
    {
        return FALSE;
    }
    *OutShadowPa = 0;

    ULONG_PTR pageBase = PAGE_ALIGN_DOWN(PageGpa);
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (PLIST_ENTRY e = g_MonitorListHead.Flink;
         e != &g_MonitorListHead;
         e = e->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
        if (mon->Active && mon->IsPebShadow && mon->PageGpa == pageBase)
        {
            *OutShadowPa = mon->ShadowPagePA +
                (PageGpa & (PAGE_SIZE - 1));
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    return found;
}

// 目标进程是否已有 PEB 影子监视（清扫线程据此跳过真实页写入）。
_Use_decl_annotations_
BOOLEAN
NpBreakPointHasPebShadow(
    PEPROCESS Process)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (Process == nullptr)
    {
        return FALSE;
    }
    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (PLIST_ENTRY e = g_MonitorListHead.Flink;
         e != &g_MonitorListHead;
         e = e->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(e, MONITOR_INFO, ListEntry);
        if (mon->Active && mon->IsPebShadow &&
            mon->OwnerProcess == Process)
        {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
    return found;
}

//
// ============================ 电源恢复 / 重新应用 ============================
//

_Use_decl_annotations_
NTSTATUS
NpBreakPointReapplyAll(
    VOID)
{
    PBREAKPOINT_INFO bps[64];
    PMONITOR_INFO mons[64];
    ULONG bpCount = 0;
    ULONG monCount = 0;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_BpListLock, &oldIrql);
    for (entry = g_BpListHead.Flink;
         entry != &g_BpListHead && bpCount < ARRAYSIZE(bps);
         entry = entry->Flink)
    {
        PBREAKPOINT_INFO bp = CONTAINING_RECORD(entry, BREAKPOINT_INFO, ListEntry);
        if (bp->Active)
        {
            bps[bpCount++] = bp;
        }
    }
    KeReleaseSpinLock(&g_BpListLock, oldIrql);

    KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
    for (entry = g_MonitorListHead.Flink;
         entry != &g_MonitorListHead && monCount < ARRAYSIZE(mons);
         entry = entry->Flink)
    {
        PMONITOR_INFO mon = CONTAINING_RECORD(entry, MONITOR_INFO, ListEntry);
        if (mon->Active)
        {
            mons[monCount++] = mon;
        }
    }
    KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

    for (ULONG i = 0; i < bpCount; i++)
    {
        BP_CPU_CONTEXT cpuContext;
        cpuContext.Bp = bps[i];
        cpuContext.Monitor = nullptr;
        cpuContext.CpuIndex = 0;
        NpBreakPointExecuteOnEachProcessor(NpBreakPointConfigureOnProcessor,
                                           &cpuContext);
    }
    for (ULONG i = 0; i < monCount; i++)
    {
        BP_CPU_CONTEXT cpuContext;
        cpuContext.Bp = nullptr;
        cpuContext.Monitor = mons[i];
        cpuContext.CpuIndex = 0;
        NpBreakPointExecuteOnEachProcessor(NpBreakPointMonitorConfigureOnProcessor,
                                           &cpuContext);
    }
    return STATUS_SUCCESS;
}

static
VOID
NpBreakPointOnPowerResume(
    _In_ NP_HV_EVENT Event,
    _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Event);
    UNREFERENCED_PARAMETER(Context);

    //
    // 睡眠期间 NPT 被清空重建为恒等映射，这里重新应用断点/监视。
    // 事件回调在 PASSIVE_LEVEL（见 NpHv.h 说明）。
    //
    NpBreakPointReapplyAll();
}

//
// ============================ 生命周期 ============================
//

_Use_decl_annotations_
NTSTATUS
NpBreakPointInitialize(
    VOID)
{
    ULONG numProcessors = NpHvGetProcessorCount();

    InitializeListHead(&g_BpListHead);
    InitializeListHead(&g_MonitorListHead);
    InitializeListHead(&g_RetiredBpList);
    InitializeListHead(&g_RetiredMonitorList);
    InitializeListHead(&g_BpPageListHead);
    InitializeListHead(&g_RetiredBpPageList);
    KeInitializeSpinLock(&g_BpListLock);
    KeInitializeSpinLock(&g_MonitorListLock);
    g_NextBpId = 1;
    g_NextMonitorId = 1;

    //
    // 每 CPU 状态挂到 VIRTUAL_PROCESSOR_DATA.ServiceData。
    //
    for (ULONG i = 0; i < numProcessors; i++)
    {
        PVIRTUAL_PROCESSOR_DATA vpData = nullptr;

        if (!NT_SUCCESS(NpHvGetProcessorData(i, &vpData)) || vpData == nullptr)
        {
            continue;
        }
        PNP_BP_CPU_STATE cpuState = static_cast<PNP_BP_CPU_STATE>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NP_BP_CPU_STATE), NP_BP_POOL_TAG));
        if (cpuState == nullptr)
        {
            continue;
        }
        RtlZeroMemory(cpuState, sizeof(NP_BP_CPU_STATE));
        vpData->ServiceData = cpuState;
    }

    //
    // 注册 VMEXIT handler（先注册先调用；未命中返回 FALSE 回落内置）。
    //
    NpHvRegisterVmExitHandler(VMEXIT_NPF, NpBreakPointHandleNpf);
    NpHvRegisterVmExitHandler(VMEXIT_EXCEPTION_BP, NpBreakPointHandleBreakpoint);
    NpHvRegisterVmExitHandler(VMEXIT_EXCEPTION_DB, NpBreakPointHandleDebug);
    NpHvRegisterVmExitHandler(VMEXIT_VMMCALL, NpBreakPointHandleVmmcall);
    NpHvRegisterPostExitCallback(NpBreakPointPostExit);

    //
    // DR 硬件断点虚拟化：注册 16 个 DR 访问 handler（DR0-7 × 读/写）。
    // VMCB 拦截位默认关闭（零开销）；NpBreakPointSetDrProbe(TRUE) 开启。
    //
    NpHvRegisterVmExitHandler(VMEXIT_DR0_READ, NpBpHandleDr0Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR1_READ, NpBpHandleDr1Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR2_READ, NpBpHandleDr2Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR3_READ, NpBpHandleDr3Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR4_READ, NpBpHandleDr4Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR5_READ, NpBpHandleDr5Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR6_READ, NpBpHandleDr6Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR7_READ, NpBpHandleDr7Read);
    NpHvRegisterVmExitHandler(VMEXIT_DR0_WRITE, NpBpHandleDr0Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR1_WRITE, NpBpHandleDr1Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR2_WRITE, NpBpHandleDr2Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR3_WRITE, NpBpHandleDr3Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR4_WRITE, NpBpHandleDr4Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR5_WRITE, NpBpHandleDr5Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR6_WRITE, NpBpHandleDr6Write);
    NpHvRegisterVmExitHandler(VMEXIT_DR7_WRITE, NpBpHandleDr7Write);

    //
    // 电源恢复后重新应用。
    //
    NpHvRegisterEvent(NpHvEventPowerResume, NpBreakPointOnPowerResume, nullptr);

    //
    // 进程退出通知：摘除该进程的用户态断点并解锁 MDL（防 0x76）。
    //
    // Ex 版要过 MmVerifyCallbackFunction（校验驱动映像签名/完整性），未签名
    // 或绕过 DSE 加载的驱动上恒返回 0xc0000022。失败时退到 legacy 版：它不
    // 做该校验，代价是回调只给 PID、不给 PEPROCESS。
    //
    NTSTATUS notifySt = PsSetCreateProcessNotifyRoutineEx(
        NpBreakPointProcessNotify, FALSE);
    if (!NT_SUCCESS(notifySt))
    {
        NpHvLogPrint("[bp] Ex process notify failed 0x%08x -> legacy fallback\n",
                     notifySt);
        notifySt = PsSetCreateProcessNotifyRoutine(
            reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE>(
                NpBreakPointProcessNotifyLegacy),
            FALSE);
        if (NT_SUCCESS(notifySt))
        {
            g_LegacyProcessNotify = TRUE;
            NpHvLogPrint("[bp] legacy process notify registered (no image "
                         "verification path)\n");
        }
        else
        {
            NpHvLogPrint("[bp] legacy process notify also failed 0x%08x "
                         "(sweep thread only)\n", notifySt);
        }
    }
    else
    {
        NpHvLogPrint("[bp] Ex process notify registered\n");
    }

    // 轮询兜底线程（进程退出清理，不依赖 notify 回调）。
    KeInitializeEvent(&g_BpSweepEvent, NotificationEvent, FALSE);
    g_BpSweepExit = FALSE;
    g_BpSweepExited = FALSE;
    g_BpSweepThread = nullptr;
    {
        HANDLE threadHandle = nullptr;
        NTSTATUS thrSt = PsCreateSystemThread(
            &threadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr,
            NpBreakPointSweepThread, nullptr);
        if (NT_SUCCESS(thrSt))
        {
            g_BpSweepThread = threadHandle;
        }
        else
        {
            NpHvLogPrint("[bp] sweep thread create failed 0x%08x\n", thrSt);
        }
    }

    NpDebugPrint("NpBreakPoint initialized (%lu CPUs).\n", numProcessors);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
NpBreakPointTeardown(
    VOID)
{
    KIRQL oldIrql;

    if (g_LegacyProcessNotify)
    {
        PsSetCreateProcessNotifyRoutine(
            reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE>(
                NpBreakPointProcessNotifyLegacy),
            TRUE);
        g_LegacyProcessNotify = FALSE;
    }
    else
    {
        PsSetCreateProcessNotifyRoutineEx(NpBreakPointProcessNotify, TRUE);
    }
    if (g_BpSweepThread != nullptr)
    {
        KIRQL _irql = KeGetCurrentIrql();
        g_BpSweepExit = TRUE;
        KeSetEvent(&g_BpSweepEvent, IO_NO_INCREMENT, FALSE);
        if (_irql >= DISPATCH_LEVEL)
        {
            NpHvLogPrint("[bp] teardown: IRQL=%u >= DISPATCH, polling\n", _irql);
            for (ULONG _i = 0; _i < 40000 && !g_BpSweepExited; _i++)
            {
                KeStallExecutionProcessor(100);
            }
            if (!g_BpSweepExited)
            {
                NpHvLogPrint("[bp] WARNING: sweep thread did not exit in 4s, handle leaked (irql=%u)\n", _irql);
                return;
            }
        }
        else
        {
            ZwWaitForSingleObject(g_BpSweepThread, FALSE, NULL);
        }
        ZwClose(g_BpSweepThread);
        g_BpSweepThread = nullptr;
    }
    NpHvUnregisterEvent(NpHvEventPowerResume, NpBreakPointOnPowerResume);

    //
    // 释放每 CPU 状态（此时已去虚拟化，无 VMEXIT 活动）。
    //
    for (ULONG i = 0; i < NpHvGetProcessorCount(); i++)
    {
        PVIRTUAL_PROCESSOR_DATA vpData = nullptr;

        if (!NT_SUCCESS(NpHvGetProcessorData(i, &vpData)) || vpData == nullptr)
        {
            continue;
        }
        if (vpData->ServiceData != nullptr)
        {
            ExFreePoolWithTag(vpData->ServiceData, NP_BP_POOL_TAG);
            vpData->ServiceData = nullptr;
        }
    }

    //
    // 释放活动断点/监视与退休链表（绝对安全）。
    //
    for (;;)
    {
        PBREAKPOINT_INFO bp = nullptr;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        if (IsListEmpty(&g_BpListHead))
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            break;
        }
        bp = CONTAINING_RECORD(g_BpListHead.Flink, BREAKPOINT_INFO, ListEntry);
        RemoveEntryList(&bp->ListEntry);
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        ExFreePoolWithTag(bp, NP_BP_POOL_TAG);   // 页资源由下面统一回收
    }
    //
    // 回收全部断点页记录（MDL / 影子页 / 进程引用）。
    //
    for (;;)
    {
        PBREAKPOINT_PAGE page = nullptr;

        KeAcquireSpinLock(&g_BpListLock, &oldIrql);
        if (IsListEmpty(&g_BpPageListHead))
        {
            KeReleaseSpinLock(&g_BpListLock, oldIrql);
            break;
        }
        page = CONTAINING_RECORD(g_BpPageListHead.Flink, BREAKPOINT_PAGE,
                                 ListEntry);
        RemoveEntryList(&page->ListEntry);
        KeReleaseSpinLock(&g_BpListLock, oldIrql);

        NpBpPageFreeResources(page);
    }
    NpBreakPointFreeRetired();

    for (;;)
    {
        PMONITOR_INFO mon = nullptr;

        KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
        if (IsListEmpty(&g_MonitorListHead))
        {
            KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
            break;
        }
        mon = CONTAINING_RECORD(g_MonitorListHead.Flink, MONITOR_INFO, ListEntry);
        RemoveEntryList(&mon->ListEntry);
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

        NpMonFinalRelease(mon);
        ExFreePoolWithTag(mon, NP_BP_POOL_TAG);
    }
    for (;;)
    {
        PMONITOR_INFO mon = nullptr;

        KeAcquireSpinLock(&g_MonitorListLock, &oldIrql);
        if (IsListEmpty(&g_RetiredMonitorList))
        {
            KeReleaseSpinLock(&g_MonitorListLock, oldIrql);
            break;
        }
        mon = CONTAINING_RECORD(g_RetiredMonitorList.Flink, MONITOR_INFO, ListEntry);
        RemoveEntryList(&mon->ListEntry);
        KeReleaseSpinLock(&g_MonitorListLock, oldIrql);

        NpMonFinalRelease(mon);
        ExFreePoolWithTag(mon, NP_BP_POOL_TAG);
    }
}
