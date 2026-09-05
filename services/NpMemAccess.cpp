/*!
    @file       NpMemAccess.cpp

    @brief      services/NpMemAccess：无痕内存读写（GVA→GPA→HPA 物理直读）。

    @details    实现要点：
                - GuestVirtualToPhysical：手工遍历 Guest 四级页表
                  （PML4E→PDPTE→PDE→PTE），支持 4KB / 2MB / 1GB 大页；
                - 物理访问一律用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)
                  （页表项读取与页内容读取都走它）；**不要**再用
                  MmGetVirtualForPhysical——它对失效帧不返回 NULL，竞态下返回
                  垃圾 VA，解引用即 0x50（历史两次蓝屏同根因）。本机曾因
                  页表项读取漏改，导致物理直读 100% 失败（pml4-np）；
                - 不做 NPT 翻译：本项目 NPT 恒等映射（GPA==HPA），且
                  直接读物理地址可绕过影子页视图（读到真实字节）；
                - PEB 影子监视：命中受保护 PEB 页时改读影子页副本。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpMemAccess.h"
#include "NpBreakPoint.h"
#include <intrin.h>

//
// ============================ 常量 ============================
//

#define PAGE_PRESENT    0x001
#define PAGE_LARGE      0x080       // PS 位（PDE/PDPTE）
#define PAGE_PFN_MASK   0x000FFFFFFFFFF000ULL

#define X64_PML4_SHIFT  39
#define X64_PDPT_SHIFT  30
#define X64_PD_SHIFT    21
#define X64_PT_SHIFT    12

#define X64_1GB_MASK    0x000000003FFFFFFFULL
#define X64_2MB_MASK    0x00000000001FFFFFULL
#define X64_4KB_MASK    0x0000000000000FFFULL

//
// ============================ 安全用户内存拷贝 ============================
//

// WDK 头未声明 MmCopyVirtualMemory；ntoskrnl.lib 已导出该符号。
extern "C"
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T NumberOfBytesCopied);

_Use_decl_annotations_
NTSTATUS
NpMemAccessCopyFromUser(
    ULONG_PTR UserSrc,
    PVOID Dst,
    ULONG Size)
{
    if (Dst == nullptr || Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (UserSrc == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    // KernelMode 拷贝不会探测用户指针，坏地址会直接写崩（0x50）。
    // 先按用户范围探测，非法指针返回 ACCESS_VIOLATION 而不是崩溃。
    __try
    {
        ProbeForRead(reinterpret_cast<PVOID>(UserSrc), Size, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    SIZE_T bytes = 0;
    // 源是用户指针、目标是内核缓冲：必须用 KernelMode，UserMode 会按
    // 用户地址探测内核缓冲导致 STATUS_ACCESS_VIOLATION（伪附加 Wait/
    // QSI 过滤都曾被此卡死）。
    NTSTATUS st = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)UserSrc,
                                      PsGetCurrentProcess(), Dst, Size,
                                      KernelMode, &bytes);
    return (NT_SUCCESS(st) && bytes == Size) ? STATUS_SUCCESS : st;
}

_Use_decl_annotations_
NTSTATUS
NpMemAccessCopyToUser(
    ULONG_PTR UserDst,
    PVOID Src,
    ULONG Size)
{
    if (Src == nullptr || Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (UserDst == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    __try
    {
        ProbeForWrite(reinterpret_cast<PVOID>(UserDst), Size, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    SIZE_T bytes = 0;
    NTSTATUS st = MmCopyVirtualMemory(PsGetCurrentProcess(), Src,
                                      PsGetCurrentProcess(), (PVOID)UserDst,
                                      Size, KernelMode, &bytes);
    return (NT_SUCCESS(st) && bytes == Size) ? STATUS_SUCCESS : st;
}

//
// ============================ 物理访问 ============================
//

static
BOOLEAN
NpReadPhysicalQword(
    _In_ ULONG_PTR Hpa,
    _Out_ PULONG64 Value
    )
{
    //
    // 与 NpReadPhysicalBytes 一致，改用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)。
    //
    // 旧实现依赖 MmGetVirtualForPhysical 的返回值：它对失效/未映射帧不返回
    // NULL（NULL 检查形同虚设），竞态下返回垃圾 VA，解引用即 0x50（系统空间
    // 坏引用 SEH 拦不住，历史两次蓝屏同根因）。
    //
    // 本机实测后果：物理直读 100% 失败，全部退化为 attached fallback——
    //   [mem] walk fail stage=pml4-np idx=1
    //   [mem] physical read failed ... status=0xc0000225 -> attached fallback
    // 根因是读页表项拿到全 0，于是 PML4E 判定 not present。旧注释里"页表帧
    // 位于全局自映射区（跨进程 CR3 可见）"的假定，在存在第三方 hypervisor
    // 的环境不成立（自映射失效）。
    //
    // MmCopyMemory 由内存管理器完成物理帧→临时映射，对无效帧优雅失败。
    // 注意：其 IRQL 上限为 APC_LEVEL；从更高 IRQL 调用时会安全返回失败，
    // 由调用方走 fallback，不会崩溃。
    //
    MM_COPY_ADDRESS src;
    SIZE_T transferred = 0;

    src.PhysicalAddress.QuadPart = static_cast<LONGLONG>(Hpa);

    if (!NT_SUCCESS(MmCopyMemory(Value,
                                 src,
                                 sizeof(ULONG64),
                                 MM_COPY_MEMORY_PHYSICAL,
                                 &transferred)) ||
        transferred != sizeof(ULONG64))
    {
        return FALSE;               // 物理帧无效/被重用：安全失败
    }
    return TRUE;
}

static
BOOLEAN
NpReadPhysicalBytes(
    _In_ ULONG_PTR Hpa,
    _Out_ PVOID Buffer,
    _In_ ULONG Size
    )
{
    //
    // 改用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)：由内存管理器完成
    // 物理帧→临时映射，对无效/已重用物理帧优雅失败。
    // 旧实现依赖 MmGetVirtualForPhysical 的返回值——它对失效帧不返回
    // NULL（NULL 检查形同虚设），竞态下返回垃圾 VA，直接解引用即
    // 0x50（系统空间坏引用 SEH 拦不住，历史两次蓝屏同根因）。
    //
    PUCHAR dst = static_cast<PUCHAR>(Buffer);
    ULONG remaining = Size;

    while (remaining > 0)
    {
        MM_COPY_ADDRESS src;
        SIZE_T transferred = 0;
        ULONG chunk;
        ULONG pageRemain = static_cast<ULONG>(PAGE_SIZE - (Hpa & (PAGE_SIZE - 1)));

        chunk = (remaining < pageRemain) ? remaining : pageRemain;
        src.PhysicalAddress.QuadPart = static_cast<LONGLONG>(Hpa);

        if (!NT_SUCCESS(MmCopyMemory(dst,
                                     src,
                                     chunk,
                                     MM_COPY_MEMORY_PHYSICAL,
                                     &transferred)) ||
            transferred != chunk)
        {
            return FALSE;               // 物理帧无效/被重用：安全失败
        }

        dst += chunk;
        Hpa += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS
NpMemAccessWrite(
    ULONG ProcessId,
    ULONG_PTR VirtualAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten)
{
    //
    // 写路径改为"附加目标进程 + 直接虚拟写"：
    //  - 物理直写无法安全实现（MmCopyMemory 只读；MmGetVirtualForPhysical
    //    返回值对失效帧不可信，且跨进程用户帧 VA 在当前 CR3 下无效）；
    //  - KeStackAttachProcess 后按 GVA 写：换页/CoW 由内存管理器正常处理，
    //    不调用任何 Nt*/句柄 API，对目标进程同样不可见（无痕语义不变）。
    //  - CoW 页会触发写时复制（旧物理直写绕过 CoW，属语义缺陷）。
    //
    PEPROCESS process = nullptr;
    NTSTATUS status;
    KAPC_STATE apcState;
    PUCHAR src = static_cast<PUCHAR>(Buffer);
    ULONG_PTR va = VirtualAddress;
    ULONG remaining = Size;

    if (Buffer == nullptr || Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BytesWritten != nullptr)
    {
        *BytesWritten = 0;
    }

    if (ProcessId == 0 || ProcessId == 4)
    {
        process = PsInitialSystemProcess;
        if (process == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        ObReferenceObject(process);
    }
    else
    {
        status = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(ProcessId)),
            &process);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    KeStackAttachProcess(process, &apcState);

    status = STATUS_SUCCESS;
    __try
    {
        while (remaining > 0)
        {
            ULONG chunk;
            ULONG pageRemain = static_cast<ULONG>(
                PAGE_SIZE - (va & (PAGE_SIZE - 1)));

            chunk = (remaining < pageRemain) ? remaining : pageRemain;
            RtlCopyMemory(reinterpret_cast<PVOID>(va), src, chunk);
            src += chunk;
            va += chunk;
            remaining -= chunk;
            if (BytesWritten != nullptr)
            {
                *BytesWritten += chunk;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();    // 部分写入：BytesRead 已累计
        if (NT_SUCCESS(status))
        {
            status = STATUS_ACCESS_VIOLATION;
        }
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);
    return status;
}

//
// ============================ Guest 页表遍历（GVA → GPA） ============================
//

static
BOOLEAN
NpGuestVirtualToPhysical(
    _In_ ULONG64 Cr3,
    _In_ ULONG_PTR Gva,
    _Out_ PULONG_PTR OutGpa
    )
{
    ULONG64 pml5e = 0, pml4e, pdpte, pde, pte;
    ULONG_PTR base;
    ULONG_PTR gpa;
    static volatile LONG s_walkDiag = 0;
    #define WALK_FAIL(stage, idx) \
        if (InterlockedIncrement(&s_walkDiag) <= 8) \
            NpHvLogPrint("[mem] walk fail stage=%s idx=%lu gva=%p\n", \
                         stage, (ULONG)(idx), (PVOID)Gva)

    // LA57（5 级页表）：CR3 指向 PML5 表，先取 PML5E 再进入 PML4。
    // 低四级（PML4/PDPT/PD/PT）的移位和掩码在 LA57 下不变。
    if ((__readcr4() & 0x1000) != 0)
    {
        base = static_cast<ULONG_PTR>(Cr3 & ~static_cast<ULONG_PTR>(0xFFF));
        if (!NpReadPhysicalQword(base + ((Gva >> 48) & 0x1FF) * 8, &pml5e))
        {
            WALK_FAIL("pml5-read", (Gva >> 48) & 0x1FF);
            return FALSE;
        }
        if ((pml5e & PAGE_PRESENT) == 0)
        {
            WALK_FAIL("pml5-np", (Gva >> 48) & 0x1FF);
            return FALSE;
        }
        base = static_cast<ULONG_PTR>(pml5e & PAGE_PFN_MASK);
    }
    else
    {
        base = static_cast<ULONG_PTR>(Cr3 & ~static_cast<ULONG_PTR>(0xFFF));
    }

    //
    // PML4E
    //
    if (!NpReadPhysicalQword(base + ((Gva >> X64_PML4_SHIFT) & 0x1FF) * 8,
                             &pml4e))
    {
        WALK_FAIL("pml4-read", (Gva >> X64_PML4_SHIFT) & 0x1FF);
        return FALSE;
    }
    if ((pml4e & PAGE_PRESENT) == 0)
    {
        WALK_FAIL("pml4-np", (Gva >> X64_PML4_SHIFT) & 0x1FF);
        return FALSE;
    }

    //
    // PDPTE（支持 1GB 大页）
    //
    if (!NpReadPhysicalQword(static_cast<ULONG_PTR>(pml4e & PAGE_PFN_MASK) +
                             ((Gva >> X64_PDPT_SHIFT) & 0x1FF) * 8, &pdpte))
    {
        WALK_FAIL("pdpt-read", (Gva >> X64_PDPT_SHIFT) & 0x1FF);
        return FALSE;
    }
    if ((pdpte & PAGE_PRESENT) == 0)
    {
        WALK_FAIL("pdpt-np", (Gva >> X64_PDPT_SHIFT) & 0x1FF);
        return FALSE;
    }
    if (pdpte & PAGE_LARGE)
    {
        *OutGpa = static_cast<ULONG_PTR>(pdpte & PAGE_PFN_MASK) +
                  (Gva & X64_1GB_MASK);
        return TRUE;
    }

    //
    // PDE（支持 2MB 大页）
    //
    if (!NpReadPhysicalQword(static_cast<ULONG_PTR>(pdpte & PAGE_PFN_MASK) +
                             ((Gva >> X64_PD_SHIFT) & 0x1FF) * 8, &pde))
    {
        WALK_FAIL("pde-read", (Gva >> X64_PD_SHIFT) & 0x1FF);
        return FALSE;
    }
    if ((pde & PAGE_PRESENT) == 0)
    {
        WALK_FAIL("pde-np", (Gva >> X64_PD_SHIFT) & 0x1FF);
        return FALSE;
    }
    if (pde & PAGE_LARGE)
    {
        *OutGpa = static_cast<ULONG_PTR>(pde & PAGE_PFN_MASK) +
                  (Gva & X64_2MB_MASK);
        return TRUE;
    }

    //
    // PTE（4KB 页）
    //
    if (!NpReadPhysicalQword(static_cast<ULONG_PTR>(pde & PAGE_PFN_MASK) +
                             ((Gva >> X64_PT_SHIFT) & 0x1FF) * 8, &pte))
    {
        WALK_FAIL("pte-read", (Gva >> X64_PT_SHIFT) & 0x1FF);
        return FALSE;
    }
    if ((pte & PAGE_PRESENT) == 0)
    {
        WALK_FAIL("pte-np", (Gva >> X64_PT_SHIFT) & 0x1FF);
        return FALSE;
    }

    gpa = static_cast<ULONG_PTR>(pte & PAGE_PFN_MASK) + (Gva & X64_4KB_MASK);
    *OutGpa = gpa;
    return TRUE;
}

//
// ============================ 进程 CR3 获取 ============================
//

static
NTSTATUS
NpGetProcessCr3(
    _In_ ULONG ProcessId,
    _Out_ PULONG64 OutCr3
    )
{
    PEPROCESS process;

    if (ProcessId == 0 || ProcessId == 4)
    {
        process = PsInitialSystemProcess;
    }
    else
    {
        NTSTATUS status = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(ProcessId)),
            &process);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ObDereferenceObject(process);
    }

    if (process == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    //
    // KPROCESS.DirectoryTableBase（EPROCESS.Pcb 内，x64 偏移 0x28）。
    // 该偏移在 Windows 10 ~ Windows 11 24H2 保持稳定（KPROCESS 布局
    // 未变动）；如遇新版本变化，可改用符号解析/特征码定位。
    // 对 System 进程为系统空间 CR3；对用户进程为用户地址空间 CR3
    // （内核映射在所有进程 CR3 下共享，读内核地址同样有效）。
    //
    *OutCr3 = *reinterpret_cast<volatile ULONG_PTR*>(
        reinterpret_cast<PUCHAR>(process) + 0x28);
    return STATUS_SUCCESS;
}

//
// ============================ 对外接口 ============================
//

// 附加目标进程后直接虚拟读（与 NpMemAccessWrite 同款语义）。
// PASSIVE 限定；SMAP 下置 EFLAGS.AC 允许内核访问用户页；__try 兜底
// 缺页/保护异常。不调用任何 Nt*/句柄 API。
static
NTSTATUS
NpMemAccessReadAttached(
    _In_ ULONG ProcessId,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ PVOID Buffer,
    _In_ ULONG Size
    )
{
    PEPROCESS process = nullptr;
    if (ProcessId == 0 || ProcessId == 4)
    {
        process = PsInitialSystemProcess;
    }
    else
    {
        NTSTATUS lst = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(ProcessId)),
            &process);
        if (!NT_SUCCESS(lst) || process == nullptr)
        {
            return lst;
        }
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR eflags = __readeflags();
    __writeeflags(eflags | 0x40000);        // EFLAGS.AC
    __try
    {
        RtlCopyMemory(Buffer, reinterpret_cast<PVOID>(VirtualAddress), Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        if (NT_SUCCESS(status))
        {
            status = STATUS_ACCESS_VIOLATION;
        }
    }
    __writeeflags(eflags);

    KeUnstackDetachProcess(&apcState);
    if (ProcessId != 0 && ProcessId != 4)
    {
        ObDereferenceObject(process);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS
NpMemAccessRead(
    ULONG ProcessId,
    ULONG_PTR VirtualAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead)
{
    ULONG64 cr3;
    NTSTATUS status;
    PUCHAR dst = static_cast<PUCHAR>(Buffer);
    ULONG remaining = Size;
    ULONG_PTR startVa = VirtualAddress;

    if (Buffer == nullptr || Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BytesRead != nullptr)
    {
        *BytesRead = 0;
    }

    status = NpGetProcessCr3(ProcessId, &cr3);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    while (remaining > 0)
    {
        ULONG_PTR gpa;
        ULONG chunk;

        if (NpGuestVirtualToPhysical(cr3, VirtualAddress, &gpa) == FALSE)
        {
            status = STATUS_NOT_FOUND;      // 页不存在/被换出
            break;
        }

        chunk = remaining;
        ULONG pageRemain = static_cast<ULONG>(PAGE_SIZE - (VirtualAddress & (PAGE_SIZE - 1)));
        if (chunk > pageRemain)
        {
            chunk = pageRemain;
        }

        ULONG_PTR readPa = gpa;
        ULONG_PTR shadowPa = 0;
        if (NpBreakPointGetPebShadowPa(gpa, &shadowPa))
        {
            readPa = shadowPa;      // PEB 影子：物理直读也返回干净副本
        }
        if (NpReadPhysicalBytes(readPa, dst, chunk) == FALSE)
        {
            static volatile LONG s_physDiag = 0;
            if (InterlockedIncrement(&s_physDiag) <= 8)
            {
                NpHvLogPrint("[mem] physical frame read fail gpa=%p va=%p\n",
                             (PVOID)gpa, (PVOID)VirtualAddress);
            }
            status = STATUS_NOT_FOUND;
            break;
        }

        dst += chunk;
        VirtualAddress += chunk;
        remaining -= chunk;
        if (BytesRead != nullptr)
        {
            *BytesRead += chunk;
        }
    }

    if (remaining == 0)
    {
        return STATUS_SUCCESS;
    }

    // 物理页表直读失败（PEB 页换出/页表帧映射不可用等）时，降级为
    // 附加目标进程直接虚拟读（PASSIVE 限定）。
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return status;
    }
    static volatile LONG s_fallbackDiag = 0;
    if (InterlockedIncrement(&s_fallbackDiag) <= 16)
    {
        NpHvLogPrint("[mem] physical read failed pid=%lu va=%p size=%lu "
                     "status=0x%08x -> attached fallback\n",
                     ProcessId, (PVOID)startVa, Size, status);
    }
    NTSTATUS ast = NpMemAccessReadAttached(ProcessId, startVa, Buffer, Size);
    if (NT_SUCCESS(ast))
    {
        if (BytesRead != nullptr)
        {
            *BytesRead = Size;
        }
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(&s_fallbackDiag, 0, 0) <= 32)
    {
        NpHvLogPrint("[mem] attached fallback FAILED pid=%lu va=%p "
                     "status=0x%08x\n",
                     ProcessId, (PVOID)startVa, ast);
    }
    return status;
}
