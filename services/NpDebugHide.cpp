/*!
    @file       NpDebugHide.cpp

    @brief      services/NpDebugHide：X64DBG 调试链路隐藏（全自动接管）。

    @details    用 NpHook（无痕 Hook）拦截调试相关系统调用：
                - NtQueryInformationProcess：调试检测 API 返回假值；
                - NtWriteVirtualMemory：写 0xCC → 转 NPT 无痕断点（已存在
                  时拦截 + 重新武装，闭环调试器 continue 流程）；
                - NtReadVirtualMemory：物理直读（无痕读）；
                - NtDebugActiveProcess：X64DBG 附加时**自动保护目标进程**
                  + 自动开启 drprobe（无需手动 dbg protect）；
                - NtSetContextThread：硬件断点（DR0-3/DR7）**自动转发**为
                  NPT 断点（执行）或 NPT 监视（写/读写）。

                回调约束：
                - 回调在 Guest 上下文（被 Hook 函数的调用线程，PASSIVE），
                  禁止调用被 Hook 函数自身；仅做 IRQL 安全操作；
                - 用户态缓冲区访问一律用 Probe* + __try/__except 保护；
                - 只对"受保护进程集"中的目标进程生效（黑名单模式除外）。

                反作弊检测面覆盖：
                - ProcessDebugPort / DebugObjectHandle / DebugFlags 伪造；
                - 断点 0xCC 不落内存（NPT 影子页承担）+ 命中/继续闭环；
                - 读内存走物理直读（不被 NtReadVirtualMemory 监控察觉）；
                - 硬件断点自动转 NPT（DR 无痕，drprobe 回显假值）。
                未覆盖（文档注明）：调试器自身模块隐藏；外部驱动绕过
                本驱动直读物理 PEB 页时仍可见真实字节（NPT 只作用于
                Guest 虚拟访问）。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpDebugHide.h"
#include "NpBreakPoint.h"
#include "NpMemAccess.h"
#include "NpSyscall.h"
#include "NpPseudoDbg.h"
#include "NpLstar.h"
#include "NpProcessHide.h"
#include <ntimage.h>        // PE 结构（IMAGE_DOS_HEADER / NT_HEADERS / EXPORT）
#include <intrin.h>         // __readmsr / __readgsqword

//
// PsLoadedModuleList 为 ntoskrnl 导出符号（头文件未引入时自声明）。
// LDR_DATA_TABLE_ENTRY 仅用前部稳定字段（Win10~Win11 x64 布局稳定）。
//
EXTERN_C PLIST_ENTRY PsLoadedModuleList;
EXTERN_C PVOID PsGetProcessPeb(PEPROCESS Process);

typedef struct _NP_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;            // 0x00
    LIST_ENTRY InMemoryOrderLinks;          // 0x10
    LIST_ENTRY InInitializationOrderLinks;  // 0x20
    PVOID DllBase;                          // 0x30
    PVOID EntryPoint;                       // 0x38
    ULONG SizeOfImage;                      // 0x40
    UNICODE_STRING FullDllName;             // 0x48
    UNICODE_STRING BaseDllName;             // 0x58
} NP_LDR_DATA_TABLE_ENTRY, *PNP_LDR_DATA_TABLE_ENTRY;

//
// 进程访问权限（winnt.h 用户态常量，内核头不引入，此处自行定义）。
//
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION    0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ              0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE             0x0020
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT           0x0010
#endif
#ifndef CONTEXT_DEBUG_REGISTERS
#define CONTEXT_DEBUG_REGISTERS      0x00000010
#endif
// PROCESS_ALL_ACCESS 全量（附加句柄足够；ObReference 用 KernelMode 仍做访问检查）
#define NP_PROCESS_DEBUG_ACCESS      (0x0001 /*TERMINATE*/ | 0x0010 /*VM_READ*/ | \
                                      0x0020 /*VM_WRITE*/ | 0x0040 /*VM_OPERATION*/ | \
                                      0x0400 /*QUERY_INFORMATION*/ | 0x0800 /*QUERY_LIMITED*/ | \
                                      0x0100 /*CREATE_THREAD*/ | 0x0200 /*SET_INFORMATION*/ | \
                                      0x0008 /*SUSPEND_RESUME*/)

//
// ============================ 受保护进程集 ============================
//

#define NP_DEBUG_HIDE_MAX_PIDS   16

//
// ============================ 受保护进程集 ============================
//

#define NP_DEBUG_HIDE_MAX_PIDS   16

// ZwQueryVirtualMemory：头文件已声明，直接使用。

static ULONG g_ProtectedPids[NP_DEBUG_HIDE_MAX_PIDS];

// 句柄表扫描用（wdm 头未声明，本地原型）
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);
#ifndef SYSTEM_EXTENDED_HANDLE_INFORMATION
#define SYSTEM_EXTENDED_HANDLE_INFORMATION 0x40
#endif
static PVOID g_ProtectedPebBase[NP_DEBUG_HIDE_MAX_PIDS];    // 对应进程 PEB 基址
static ULONG g_ProtectedDebuggerPid[NP_DEBUG_HIDE_MAX_PIDS]; // 附加者 PID 锚点
static KSPIN_LOCK g_PidLock;
static volatile BOOLEAN g_HideEnabled = FALSE;
static volatile ULONG g_ProtectMode /* ALREADY_REGISTERED tolerated in SetEnabled */ = NPHV_DEBUG_MODE_WHITELIST;

// WorkQueue for VMMCALL@DISPATCH -> PASSIVE (true deviceless)
static WORK_QUEUE_ITEM g_HcWorkItem;
static BOOLEAN g_HcWorkEnable;
static volatile LONG g_HcWorkPending = 0;
static volatile NTSTATUS g_HcWorkStatus = STATUS_SUCCESS;
static KEVENT g_HcWorkEvent;

static VOID NpHcDbgHideWorker(PVOID Context){
    UNREFERENCED_PARAMETER(Context);
    BOOLEAN en = g_HcWorkEnable;
    NTSTATUS st1 = NpDebugHideSetEnabled(en);
    NTSTATUS st2 = STATUS_SUCCESS;
    // Prochide同步开关（与dbg hide同开关，复位线程调速联动）
    st2 = NpProcessHideSetEnabled(en);
    g_HcWorkStatus = NT_SUCCESS(st1) ? st2 : st1;
    NpHvLogPrint("[hc] DbgHide worker enable=%u st1=0x%08x st2=0x%08x\n", (ULONG)en, st1, st2);
    InterlockedExchange(&g_HcWorkPending, 0);
    KeSetEvent(&g_HcWorkEvent, IO_NO_INCREMENT, FALSE);
}

NTSTATUS NpDebugHideQueueEnable(BOOLEAN Enable){
    if(InterlockedCompareExchange(&g_HcWorkPending, 1, 0) != 0){
        NpHvLogPrint("[hc] DbgHide queue busy enable=%u\n", (ULONG)Enable);
        return STATUS_DEVICE_BUSY;
    }
    g_HcWorkEnable = Enable;
    g_HcWorkStatus = STATUS_PENDING;
    KeClearEvent(&g_HcWorkEvent);
    ExInitializeWorkItem(&g_HcWorkItem, NpHcDbgHideWorker, NULL);
    ExQueueWorkItem(&g_HcWorkItem, DelayedWorkQueue);
    NpHvLogPrint("[hc] DbgHide queued enable=%u\n", (ULONG)Enable);
    return STATUS_PENDING;
}

BOOLEAN NpDebugHideIsWorkPending(VOID){
    return InterlockedCompareExchange(&g_HcWorkPending, 0, 0) != 0;
}

//
// 跨版本 PEB 调试标记清除（零内部偏移依赖）。
// 通过文档化 API 获取 PEB 基址，附着后清除 BeingDebugged 和 NtGlobalFlag。
// 所有使用的接口均为微软公开文档化的稳定 API：
//   ObOpenObjectByPointer / ZwQueryInformationProcess / PROCESS_BASIC_INFORMATION
// PASSIVE_LEVEL 调用。
//

// wdm 头可能未声明此 API（ntoskrnl 导出 ✓）
extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef struct _NPHV_PBI {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} NPHV_PBI;

static
VOID
NpDbgHideClearDebugMarks(
    _In_ PEPROCESS proc
    )
{
    //
    // 步骤 ① 获取进程句柄（附着前在调用者上下文完成）。
    //
    HANDLE hProc = nullptr;
    if (!NT_SUCCESS(ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE,
            nullptr, PROCESS_QUERY_INFORMATION, *PsProcessType,
            KernelMode, &hProc)))
    {
        return;
    }

    //
    // 步骤 ② 查询 PEB 基址（ZwQueryInformationProcess 是文档化 API，
    // OS 内核负责填入正确的 PEB 地址——无需猜测任何内部偏移）。
    //
    ULONG64 pebVa = 0;
    {
        // PROCESS_BASIC_INFORMATION = { ExitStatus, PebBaseAddress,
        //   AffinityMask, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId }
        // x64 布局固定，PebBaseAddress 在 +0x08。
        ULONG64 pbi[6] = {0};   // 48 bytes ≥ sizeof(PROCESS_BASIC_INFORMATION)
        NTSTATUS s2 = ZwQueryInformationProcess(hProc, 0 /*ProcessBasicInformation*/,
                                                pbi, sizeof(pbi), nullptr);
        if (NT_SUCCESS(s2))
        {
            pebVa = pbi[1];     // PebBaseAddress @ offset 8
        }
    }
    ZwClose(hProc);

    if (pebVa == 0)
    {
        return;                 // 无法获取 PEB 基址 → 安全跳过
    }

    //
    // 步骤 ③ 附着目标进程清除标记。PEB+0x02=BeingDebugged、PEB+0xBC=NtGlobalFlag
    // 的偏移自 Windows NT 以来从未变过（x64 用户态结构）。
    //
    KAPC_STATE apcState;
    KeStackAttachProcess(proc, &apcState);
    __try
    {
        *(volatile UCHAR*)(pebVa + 0x02) = 0;
        *(volatile ULONG*)(pebVa + 0xBC) &= ~0x70UL;    // FLG_HEAP_* 位
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    KeUnstackDetachProcess(&apcState);
}

static
VOID
NpDbgHideSweepMarks(
    ULONG Pid
    )
{
    //
    // 兜底清除：DAP hook 可能因影子页 C 态暴露窗口被绕过（附加动作
    // 没被拦截 → 无人清 BeingDebugged）。本函数由 NpGetProtectedTargetPid
    // 节流调用——五个 dbghide hook 任何一个命中都会路过，字节级标记
    // 最终收敛到毫秒级。
    //
    PEPROCESS proc = nullptr;

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return;
    }

    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(Pid), &proc)) ||
        proc == nullptr)
    {
        return;
    }

    // NPT PEB 影子在位时真实页无需周期写入（Guest/物理直读都走影子）。
    if (NpBreakPointHasPebShadow(proc))
    {
        ObDereferenceObject(proc);
        return;
    }

    NpDbgHideClearDebugMarks(proc);
    ObDereferenceObject(proc);
}

//
// Low-frequency PEB sweep thread. BeingDebugged/NtGlobalFlag are set only
// once at attach; keep a 100ms safety net instead of 1ms polling (less CPU,
// fewer detectable periodic writes). Attach-time clearing is done on-demand.
//
static KEVENT g_HideSweepEvent;
static HANDLE g_HideSweepThread = nullptr;
static volatile BOOLEAN g_HideSweepExit = FALSE;
static volatile BOOLEAN g_HideSweepExited = FALSE;

static
VOID
NpDebugHideSweepThread(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER interval;
    interval.QuadPart = -10000LL * 100; // 100ms safety net (BeingDebugged is set once at attach, not continuously)
    ULONG pids[NP_DEBUG_HIDE_MAX_PIDS];
    for (;;)
    {
        KeWaitForSingleObject(&g_HideSweepEvent, Executive, KernelMode,
                              FALSE, &interval);
        if (g_HideSweepExit) break;

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_PidLock, &oldIrql);
        for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
            pids[i] = g_ProtectedPids[i];
        KeReleaseSpinLock(&g_PidLock, oldIrql);

        for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
        {
            if (pids[i] != 0) NpDbgHideSweepMarks(pids[i]);
        }
    }
    g_HideSweepExited = TRUE;
    PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// Hook 句柄（NpHookInstallHook 返回；NULL = 未安装）。
//
static PHOOK_INFO g_HookNtQIP = nullptr;    // NtQueryInformationProcess
static PHOOK_INFO g_HookNtWVM = nullptr;    // NtWriteVirtualMemory
static PHOOK_INFO g_HookNtRVM = nullptr;    // NtReadVirtualMemory
static PHOOK_INFO g_HookNtDAP = nullptr;    // NtDebugActiveProcess（自动 protect）
static PHOOK_INFO g_HookNtSCT = nullptr;    // NtSetContextThread????????


//
// ============================ 受保护进程集操作 ============================
//

_Use_decl_annotations_
NTSTATUS
NpDebugHideProtectProcess(
    ULONG ProcessId,
    BOOLEAN Protect)
{
    KIRQL oldIrql;

    if (ProcessId == 0 || ProcessId == 4)
    {
        return STATUS_INVALID_PARAMETER;    // 不允许保护 System/Idle
    }

    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    if (Protect != FALSE)
    {
        for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
        {
            if (g_ProtectedPids[i] == ProcessId)
            {
                KeReleaseSpinLock(&g_PidLock, oldIrql);
                return STATUS_ALREADY_REGISTERED;
            }
        }
        for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
        {
            if (g_ProtectedPids[i] == 0)
            {
                g_ProtectedPids[i] = ProcessId;
                KeReleaseSpinLock(&g_PidLock, oldIrql);

                //
                // 附带动作：捕获 PEB 基址并清除原始调试标记
                // （BeingDebugged / NtGlobalFlag）。DAP 自动保护与本手动
                // 接口共用本函数，两条路径都覆盖。
                //
                do {
                    PEPROCESS proc2 = nullptr;
                    if (NT_SUCCESS(PsLookupProcessByProcessId(
                            ULongToHandle(ProcessId), &proc2)) && proc2 != nullptr)
                    {
                        NpDbgHideClearDebugMarks(proc2);
                        ObDereferenceObject(proc2);
                    }
                } while (0);

                NpHvLogPrint("[dbghide] protect pid=%lu\n", ProcessId);
                return STATUS_SUCCESS;
            }
        }
        KeReleaseSpinLock(&g_PidLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
    {
        if (g_ProtectedPids[i] == ProcessId)
        {
            g_ProtectedPids[i] = 0;
            g_ProtectedPebBase[i] = nullptr;
            KeReleaseSpinLock(&g_PidLock, oldIrql);
            NpBreakPointUninstallPebShadowByPid(ProcessId);
            NpHvLogPrint("[dbghide] unprotect pid=%lu\n", ProcessId);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return STATUS_NOT_FOUND;
}

//
// 登记某受保护进程当前的调试器 PID（附加瞬间捕获的锚点）。
//
VOID
NpDebugHideNoteDebugger(
    ULONG VictimPid,
    ULONG DebuggerPid
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
    {
        if (g_ProtectedPids[i] == VictimPid)
        {
            g_ProtectedDebuggerPid[i] = DebuggerPid;
            break;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}

_Use_decl_annotations_
BOOLEAN
NpDebugHideIsDebuggerOf(
    ULONG DebuggerPid,
    ULONG VictimPid
    )
{
    KIRQL oldIrql;
    BOOLEAN isDbg = FALSE;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
    {
        if (g_ProtectedPids[i] == VictimPid &&
            g_ProtectedDebuggerPid[i] == DebuggerPid)
        {
            isDbg = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return isDbg;
}

//
// 进程退出联动清理：受害 PID 退出时移出保护集（防 PID 复用误保护），
// 同时清 PEB 基址与调试器锚点。由进程通知回调调用。
//
VOID
NpDebugHideOnProcessExit(
    ULONG Pid
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
    {
        if (g_ProtectedPids[i] == Pid)
        {
            g_ProtectedPids[i] = 0;
            g_ProtectedPebBase[i] = nullptr;
            g_ProtectedDebuggerPid[i] = 0;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}


_Use_decl_annotations_
BOOLEAN
NpDebugHideIsProtected(
    ULONG ProcessId)
{
    KIRQL oldIrql;
    BOOLEAN inSet = FALSE;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
    {
        if (g_ProtectedPids[i] == ProcessId)
        {
            inSet = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);

    //
    // 按模式取反：
    //   白名单（默认）：集合 = 隐藏目标 → 命中集合才隐藏；
    //   黑名单：集合 = 排除目标 → 未命中集合（除注册 PID 外）全部隐藏。
    //
    if (g_ProtectMode == NPHV_DEBUG_MODE_BLACKLIST)
    {
        return !inSet;
    }
    return inSet;
}

_Use_decl_annotations_
NTSTATUS
NpDebugHideSetMode(
    ULONG Mode)
{
    if (Mode != NPHV_DEBUG_MODE_WHITELIST && Mode != NPHV_DEBUG_MODE_BLACKLIST)
    {
        return STATUS_INVALID_PARAMETER;
    }

    g_ProtectMode = Mode;
    NpHvLogPrint("[dbghide] mode=%s\n",
                 (Mode == NPHV_DEBUG_MODE_BLACKLIST) ? "blacklist (hide all)" :
                                                       "whitelist");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
ULONG
NpDebugHideGetMode(
    VOID)
{
    return g_ProtectMode;
}

_Use_decl_annotations_
ULONG
NpDebugHideGetProtectedCount(
    VOID)
{
    KIRQL oldIrql;
    ULONG count = 0;

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
    {
        if (g_ProtectedPids[i] != 0)
        {
            count++;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return count;
}

_Use_decl_annotations_
BOOLEAN
NpDebugHideIsEnabled(
    VOID)
{
    return g_HideEnabled;
}

//
// ============================ 辅助 ============================
//

// 从句柄解析目标进程并检查是否受保护（返回受保护 PID；否则 0）。
static
ULONG
NpGetProtectedTargetPid(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    PEPROCESS process = nullptr;
    NTSTATUS status;
    ULONG pid = 0;

    status = ObReferenceObjectByHandle(ProcessHandle,
                                       DesiredAccess,
                                       *PsProcessType,
                                       KernelMode,
                                       reinterpret_cast<PVOID*>(&process),
                                       nullptr);
    if (!NT_SUCCESS(status) || process == nullptr)
    {
        return 0;
    }

    pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
        PsGetProcessId(process)));
    ObDereferenceObject(process);

    if (!NpDebugHideIsProtected(pid))
    {
        return 0;
    }

    //
    // 兜底 PEB 标记清除（节流：每 8 次命中执行一次）。覆盖 DAP 被影子页
    // 暴露窗口绕过的情形——调试期间 QIP/RVM/WVM/SCT 高频命中，字节级
    // 标记在毫秒内必然被刷掉。
    //
    {
        static volatile LONG s_SweepCounter = 0;
        if ((InterlockedIncrement(&s_SweepCounter) & 7) == 0)
        {
            NpDbgHideSweepMarks(pid);
        }
    }

    return pid;
}

//
// ============================ 回调 ============================
//

/*!
    @brief      NtQueryInformationProcess 伪造。
    @details    只处理受保护进程的调试检测类查询：
                - ProcessDebugPort(7)      → 0（无调试端口）
                - ProcessDebugObjectHandle(0x1E) → STATUS_PORT_NOT_SET
                - ProcessDebugFlags(0x1F)  → 1（允许调试，未附加）
 */
static
BOOLEAN
NpDbgHideQueryProcessInfo(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    ULONG infoClass = static_cast<ULONG>(Ctx->Rdx);
    ULONG pid;
    ULONG length = static_cast<ULONG>(Ctx->R9);

    //
    // 高 IRQL 调用（DPC 等场景）放行原函数——本回调需 ObReference
    // 对象句柄（PASSIVE 限定），且调试检测查询几乎都来自 PASSIVE。
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }

    //
    // 只处理调试检测类。
    //
    if (infoClass != 7 && infoClass != 0x1E && infoClass != 0x1F)
    {
        return FALSE;
    }

    pid = NpGetProtectedTargetPid(reinterpret_cast<HANDLE>(Ctx->Rcx),
                                  PROCESS_QUERY_INFORMATION);
    if (pid == 0)
    {
        return FALSE;                       // 非受保护进程，放行
    }

    __try
    {
        switch (infoClass)
        {
        case 7:                             // ProcessDebugPort（8 字节）
            if (length < sizeof(ULONG_PTR))
            {
                return FALSE;               // 长度不足，放行原函数
            }
            {
                ULONG_PTR zero = 0;
                if (!NT_SUCCESS(NpMemAccessCopyToUser(Ctx->R8, &zero,
                                                      sizeof(zero))))
                {
                    return FALSE;
                }
            }
            Ctx->Rax = 0;                   // STATUS_SUCCESS
            break;
        case 0x1E:                          // ProcessDebugObjectHandle（8 字节）
            if (length < sizeof(PVOID))
            {
                return FALSE;
            }
            {
                ULONG_PTR nullHandle = 0;
                if (!NT_SUCCESS(NpMemAccessCopyToUser(Ctx->R8, &nullHandle,
                                                      sizeof(nullHandle))))
                {
                    return FALSE;
                }
            }
            Ctx->Rax = 0xC0000353;          // STATUS_PORT_NOT_SET
            break;
        case 0x1F:                          // ProcessDebugFlags（4 字节）
            if (length < sizeof(ULONG))
            {
                return FALSE;
            }
            {
                ULONG debugAllowed = 1;
                if (!NT_SUCCESS(NpMemAccessCopyToUser(Ctx->R8, &debugAllowed,
                                                      sizeof(debugAllowed))))
                {
                    return FALSE;
                }
            }
            Ctx->Rax = 0;
            break;
        default:
            return FALSE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Ctx->Rax = GetExceptionCode();
    }
    return TRUE;
}

/*!
    @brief      NtWriteVirtualMemory：软件断点（0xCC）拦截。
    @details    受保护进程 + 写内容首字节为 0xCC → 转为 NPT 无痕断点
                （DEBUGGER 透传模式）并拦截本次写——内存保持原始字节，
                调试器（X64DBG）认为断点已设（返回成功）。
 */
static
BOOLEAN
NpDbgHideWriteVirtualMemory(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    PEPROCESS process = nullptr;
    NTSTATUS status;
    ULONG pid;
    BOOLEAN isInt3 = FALSE;

    //
    // 高 IRQL 调用放行（ObReference/AttachProcess 均 PASSIVE 限定）。
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(reinterpret_cast<HANDLE>(Ctx->Rcx),
                                       PROCESS_VM_WRITE,
                                       *PsProcessType,
                                       KernelMode,
                                       reinterpret_cast<PVOID*>(&process),
                                       nullptr);
    if (!NT_SUCCESS(status) || process == nullptr)
    {
        return FALSE;
    }

    pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
        PsGetProcessId(process)));
    if (!NpDebugHideIsProtected(pid))
    {
        ObDereferenceObject(process);
        return FALSE;
    }

    //
    // 读取调试器写缓冲首字节（用户态指针，SEH 保护）。
    //
    UCHAR firstByte = 0;
    if (Ctx->R9 >= 1 &&
        NT_SUCCESS(NpMemAccessCopyFromUser(Ctx->R8, &firstByte, 1)))
    {
        isInt3 = (firstByte == 0xCC);
    }

    if (!isInt3)
    {
        //
        // 调试器删除/禁用断点：写回原字节 → 摘除对应的 NPT 断点。
        // continue 恢复步也会写回原字节，但随后会重写 0xCC 重新安装。
        //
        if (NpBreakPointTryDeleteDebuggerBp(
                static_cast<ULONG_PTR>(Ctx->Rdx), firstByte,
                static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                    PsGetCurrentProcessId())) != pid,
                static_cast<ULONG>(Ctx->R9)))
        {
            ObDereferenceObject(process);
            Ctx->Rax = 0;               // 真实页本就没有 CC，拦截本次写即可
            return TRUE;
        }

        //
        // 断点页上的非原字节/多字节写（调试器打补丁）：不改变断点状态，
        // 写入真实页并刷新影子页，让补丁对执行生效。
        //
        if (NpBreakPointIsDebuggerBpAt(static_cast<ULONG_PTR>(Ctx->Rdx)))
        {
            NTSTATUS pr = NpBreakPointRefreshShadowOnPatch(
                static_cast<ULONG_PTR>(Ctx->Rdx), process,
                reinterpret_cast<PVOID>(Ctx->R8),
                static_cast<ULONG>(Ctx->R9));
            ObDereferenceObject(process);
            if (NT_SUCCESS(pr))
            {
                Ctx->Rax = 0;
                return TRUE;
            }
            return FALSE;               // 刷新失败：放行原写（真实页落补丁）
        }

        //
        // 非 CC 写：直接放行落真实页。补丁视图已移除（MDL 泄漏 + 执行/
        // 读取分叉可被 R0 反作弊检测）。
        //
        ObDereferenceObject(process);
        return FALSE;                       // 普通写，放行
    }

    //
    // 转 NPT 无痕断点（DEBUGGER 模式：命中注入 #BP 给 Guest 调试体系）。
    //
    status = NpBreakPointInstallEx(static_cast<ULONG_PTR>(Ctx->Rdx),
                                   NPHV_BP_FLAG_DEBUGGER,
                                   process,
                                   nullptr);
    ObDereferenceObject(process);

    if (status == STATUS_ALREADY_REGISTERED)
    {
        //
        // 非暂停期的 0xCC 重写不是 step-over 的重新武装（那必然发生在
        // 暂停期内），而是删除时写回了被污染的 "原字节" —— x64dbg 的
        // BpEnable() 会 MemRead 重读 oldbytes，叠加我们对调试器呈现 0xCC
        // 的读视图，oldbytes 可能被污染成 0xCC。此时应判为删除。
        //
        if (NpBreakPointDeleteByCcWrite(static_cast<ULONG_PTR>(Ctx->Rdx)))
        {
            Ctx->Rax = 0;               // 吞掉本次写，断点已摘除
            return TRUE;
        }

        //
        // 断点已存在 = 调试器（X64DBG）重写 0xCC 恢复断点：
        // 拦截本次写（内存仍无 CC），并重新武装 NPT（NX=1）。
        // 这同时结束 DebuggerPaused 暂停期（断点命中 → 调试器继续 →
        // 恢复断点 → 重新武装 → 下次执行到断点再触发）。
        //
        NpBreakPointReArmByAddress(static_cast<ULONG_PTR>(Ctx->Rdx));
        Ctx->Rax = 0;
        return TRUE;
    }

    if (!NT_SUCCESS(status))
    {
        //
        // 安装失败（页不在内存/池耗尽）：放行原写（调试器断点仍生效，
        // 只是非无痕）。
        //
        return FALSE;
    }

    NpHvLogPrint("[dbghide] 0xCC write @0x%p pid=%lu -> NPT breakpoint\n",
                 reinterpret_cast<PVOID>(Ctx->Rdx),
                 pid);
    Ctx->Rax = 0;                           // STATUS_SUCCESS：内存未被修改
    return TRUE;
}

/*!
    @brief      NtReadVirtualMemory：无痕读。
    @details    受保护进程 → NpMemAccess 物理直读（真实内容，无 CC）。
 */
static
BOOLEAN
NpDbgHideReadVirtualMemory(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    ULONG pid;
    ULONG bytesRead = 0;
    NTSTATUS status;

    //
    // 高 IRQL 调用放行（ObReference 需 PASSIVE）。
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }

    pid = NpGetProtectedTargetPid(reinterpret_cast<HANDLE>(Ctx->Rcx),
                                  PROCESS_VM_READ);
    if (pid == 0)
    {
        return FALSE;
    }

    if (Ctx->R9 == 0 || Ctx->R9 > NPHV_MAX_MEMORY_IO)
    {
        return FALSE;                       // 超范围放行（原函数分段处理）
    }

    // 物理直读先落到内核临时缓冲，再经 NpMemAccessCopyToUser 拷给用户，
    // 避免在 SMAP/KPTI 环境下内核直接写用户页触发 0x50。
    ULONG size = static_cast<ULONG>(Ctx->R9);
    PUCHAR temp = static_cast<PUCHAR>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'hRdV'));
    if (temp == nullptr)
    {
        return FALSE;
    }

    __try
    {
        status = NpMemAccessRead(pid,
                                 static_cast<ULONG_PTR>(Ctx->Rdx),
                                 temp,
                                 size,
                                 &bytesRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ExFreePoolWithTag(temp, 'hRdV');
        return FALSE;                       // 物理读异常，放行原函数
    }
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(temp, 'hRdV');
        return FALSE;                       // 失败放行（页不在内存等）
    }

    //
    // PEB 调试标记擦除：物理直读的结果里也不能出现 BeingDebugged /
    // NtGlobalFlag——反作弊跨进程 RPM 扫描目标 PEB 时只允许读到干净值。
    //
    {
        ULONG_PTR start = static_cast<ULONG_PTR>(Ctx->Rdx);
        PUCHAR outBuf = temp;
        KIRQL q;
        PVOID peb = nullptr;

        KeAcquireSpinLock(&g_PidLock, &q);
        for (ULONG i = 0; i < NP_DEBUG_HIDE_MAX_PIDS; i++)
        {
            if (g_ProtectedPids[i] == pid)
            {
                peb = g_ProtectedPebBase[i];
                break;
            }
        }
        KeReleaseSpinLock(&g_PidLock, q);

        if (peb != nullptr)
        {
            static const struct {
                ULONG_PTR off;
                ULONG len;
            } marks[2] = {
                { 0x02, 1 },      // BeingDebugged
                { 0xBC,  4 },      // NtGlobalFlag
            };
            ULONG_PTR s = start;
            ULONG_PTR e = start + size;

            __try
            {
                for (int m = 0; m < 2; m++)
                {
                    ULONG_PTR ms = (ULONG_PTR)peb + marks[m].off;
                    ULONG_PTR me = ms + marks[m].len;
                    if (ms < e && s < me)               // 有交集
                    {
                        ULONG_PTR b0 = (ms > s) ? ms : s;
                        ULONG_PTR b1 = (me < e) ? me : e;
                        for (ULONG_PTR p = b0; p < b1; p++)
                        {
                            outBuf[p - s] = 0;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // 缓冲异常：放弃擦除，数据已安全返回
            }
        }
    }

    //
    // 断点页：仅对已附加的调试器呈现 0xCC。
    //
    // 不加这段的话，调试器写 0xCC（被 WVM 拦截成 NPT 断点）后读回真实字节，
    // 会认为"断点没了" —— 删除时不再写回原字节，try-delete 探测不到删除
    // 意图，断点残留：取消后运行目标函数仍被断下，并因未预期断点而崩溃。
    // 其它调用方（内存扫描/反作弊/目标自身）仍拿到真实字节，无痕性不变。
    //
    //
    // 断点页：仅对已附加的调试器呈现 0xCC。
    //
    // 不加这段的话，调试器写 0xCC（被 WVM 拦截成 NPT 断点）后读回真实字节，
    // 会认为"断点没了" —— 删除时（TitanEngine DeleteBPX 先读内存验证，
    // 读到非 0xCC 就认为断点已不在、不写回原字节）驱动侧收不到任何信号，
    // 断点残留：取消后运行目标函数仍被断下。实测日志 rvm 无一条 -cc 标记，
    // 证明此前 overlay 从未生效 —— 判据用了 NpPseudoDbgFindByDebugger，
    // 而真实附加模式下 pseudo 会话不存在，恒返回 FALSE。
    //
    // 修法：改查真实附加的锚点记录（NpDebugHideNoteDebugger 在 DAP 拦截处
    // 登记）。其它调用方（内存扫描/反作弊/目标自身）仍拿到真实字节。
    //
    BOOLEAN rvmCcView = FALSE;
    {
        ULONG callerPid = static_cast<ULONG>(
            reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));

        if (NpDebugHideIsDebuggerOf(callerPid, pid))
        {
            rvmCcView = NpBreakPointOverlayCcForRead(pid,
                                                     static_cast<ULONG_PTR>(Ctx->Rdx),
                                                     size,
                                                     temp);
        }
    }

    //
    // 注：NumberOfBytesRead（第五参数，栈上）未回填——多数调用方传 NULL。
    //
    // 诊断：记录 RVM 读取的目标 VA/大小/状态/首 8 字节，用于确认 x64dbg
    // 收到的是否正确。
    //
    // 节流 512；但**读取范围覆盖了活动断点地址的一律无条件打印**（带
    // -cc 标记）——这正是判断"调试器删除断点时读到了什么"的关键证据，
    // 丢一次就得让用户再复现一轮。上一版统一节流 64，导致该证据被吞掉，
    // 据此得出的"调试器没读"结论是错的。
    {
        static volatile LONG s_rvmDiag = 0;
        if (rvmCcView || InterlockedIncrement((volatile LONG *)&s_rvmDiag) <= 512)
        {
            PUCHAR b = temp;
            NpHvLogPrint("[dbghide] rvm%s pid=%lu va=%p size=%lu st=0x%08x "
                         "b=%02X %02X %02X %02X %02X %02X %02X %02X\n",
                         rvmCcView ? "-cc" : "",
                         pid, (PVOID)(ULONG_PTR)Ctx->Rdx, size, status,
                         b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        }
    }

    if (!NT_SUCCESS(NpMemAccessCopyToUser((ULONG_PTR)Ctx->R8, temp, bytesRead)))
    {
        ExFreePoolWithTag(temp, 'hRdV');
        return FALSE;                       // 用户缓冲无效，放行原函数
    }
    ExFreePoolWithTag(temp, 'hRdV');
    Ctx->Rax = status;
    return TRUE;
}

/*!
    @brief      NtDebugActiveProcess：自动识别调试目标。
    @details    X64DBG 附加目标进程时调用本函数。解析目标进程并：
                - 白名单模式：自动加入受保护进程集（无需手动 dbg protect）；
                - 自动开启 DR 探测（drprobe）——调试会话开始。
                放行原函数（附加正常进行）。
 */
static
BOOLEAN
NpDbgHideDebugActiveProcess(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    PEPROCESS process = nullptr;
    NTSTATUS status;
    ULONG pid;

    //
    // 高 IRQL 调用放行（ObReference 需 PASSIVE）。
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }

    status = ObReferenceObjectByHandle(reinterpret_cast<HANDLE>(Ctx->Rcx),
                                       NP_PROCESS_DEBUG_ACCESS,
                                       *PsProcessType,
                                       KernelMode,
                                       reinterpret_cast<PVOID*>(&process),
                                       nullptr);
    if (!NT_SUCCESS(status) || process == nullptr)
    {
        return FALSE;
    }

    pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
        PsGetProcessId(process)));
    ObDereferenceObject(process);

    if (pid == 0 || pid == 4)
    {
        return FALSE;
    }

    //
    // 伪附加联动（LSTAR 接管时）：DAP 不再走真实附加（不建 DEBUG_OBJECT、
    // 不写 DebugPort），只登记伪会话。EPROCESS 全程零痕迹。
    //
    if (NpLstarIsEnabled())
    {
        ULONG sid = 0;
        NTSTATUS ps = NpPseudoDbgCreateSession(
            pid, static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                PsGetCurrentProcessId())), &sid);
        if (NT_SUCCESS(ps))
        {
            if (NpDebugHideGetMode() == NPHV_DEBUG_MODE_WHITELIST &&
                !NpDebugHideIsProtected(pid))
            {
                NpDebugHideProtectProcess(pid, TRUE);
            }
            NpDebugHideNoteDebugger(
                pid, static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                    PsGetCurrentProcessId())));
            NpBreakPointSetDrProbe(TRUE);
            NpPseudoDbgSnapshot(
                pid, static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                    PsGetCurrentProcessId())));
            Ctx->Rax = STATUS_SUCCESS;
            return TRUE;
        }
        if (ps == STATUS_ALREADY_REGISTERED)
        {
            Ctx->Rax = STATUS_SUCCESS;
            return TRUE;
        }
        // 创建失败：回落到真实附加（旧行为）。
    }

    //
    // 白名单模式：自动保护（目标被隐藏）；黑名单模式目标本就被隐藏，无需操作。
    //
    if (NpDebugHideGetMode() == NPHV_DEBUG_MODE_WHITELIST &&
        !NpDebugHideIsProtected(pid))
    {
        NpDebugHideProtectProcess(pid, TRUE);
    }

    //
    // 记录附加者身份（DebuggerPid 锚点）：后续写入分流的"自己人"依据。
    //
    NpDebugHideNoteDebugger(pid,
        static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())));

    //
    // 调试会话开始：自动开启 DR 硬件断点虚拟化。
    //
    NpBreakPointSetDrProbe(TRUE);

    //
    // 调用原函数真正完成附加。内核会在附加路径上把目标 PEB.BeingDebugged
    // 置回 1——所以必须等原函数返回后（而非注册保护时）再做最后一次清除，
    // 否则"先 dbg protect、后附加"的流程会被内核重新弄脏。
    // 与 prochide 的 g_OrigQSI 同款原理：回调上下文里直调原地址执行的是
    // 干净视图的原代码，不会重入本 hook。
    //
    {
        typedef NTSTATUS (*PFN_NtDebugActiveProcess)(HANDLE, HANDLE);
        PFN_NtDebugActiveProcess orig =
            (PFN_NtDebugActiveProcess)g_HookNtDAP->OriginalAddress;

        status = orig(reinterpret_cast<HANDLE>(Ctx->Rcx),
                      reinterpret_cast<HANDLE>(Ctx->Rdx));
        if (!NT_SUCCESS(status))
        {
            Ctx->Rax = (ULONG_PTR)status;
            return TRUE;                    // 附加失败：如实返回错误码
        }
    }

    //
    // 附加成功：补记 PEB 基址（自动保护路径可能尚未记录）并清除调试标记。
    //
    {
        PEPROCESS proc2 = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                ULongToHandle(pid), &proc2)) && proc2 != nullptr)
        {
            NpDbgHideClearDebugMarks(proc2);
            {
                ULONG monId = 0;
                NTSTATUS mst = NpBreakPointInstallPebShadow(proc2, &monId);
                if (mst != STATUS_ALREADY_REGISTERED && !NT_SUCCESS(mst))
                {
                    NpHvLogPrint("[dbghide] peb shadow install failed "
                                 "pid=%lu status=0x%08x\n", pid, mst);
                }
            }
            ObDereferenceObject(proc2);
        }
    }

    NpHvLogPrint("[dbghide] auto-protect pid=%lu (DebugActiveProcess)\n", pid);
    Ctx->Rax = (ULONG_PTR)STATUS_SUCCESS;
    return TRUE;
}

/*!
    @brief      NtSetContextThread：自动接管硬件断点。
    @details    X64DBG 设硬件断点 = 写 CONTEXT.Dr0-3/Dr7。解析使能槽并
                自动转发为 NPT 断点/监视（执行断点→NPT 断点，写/读写断点
                →NPT 监视），同时放行原调用（调试器正常设上下文）。
                仅处理受保护进程的线程。
 */
static
BOOLEAN
NpDbgHideSetContextThread(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    PCONTEXT ctx = nullptr;
    PETHREAD thread = nullptr;
    PEPROCESS process;
    ULONG pid;
    NTSTATUS status;

    //
    // 高 IRQL 调用放行（ObReference 需 PASSIVE）。
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }

    if (Ctx->R9 < sizeof(CONTEXT))
    {
        return FALSE;
    }

    CONTEXT ctxCopy;
    if (!NT_SUCCESS(NpMemAccessCopyFromUser(Ctx->R8, &ctxCopy,
                                            sizeof(ctxCopy))))
    {
        return FALSE;
    }
    ctx = &ctxCopy;

    if ((ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == 0)
    {
        return FALSE;                       // 非 DR 相关设置，放行
    }

    status = ObReferenceObjectByHandle(reinterpret_cast<HANDLE>(Ctx->Rcx),
                                       THREAD_SET_CONTEXT,
                                       *PsThreadType,
                                       KernelMode,
                                       reinterpret_cast<PVOID*>(&thread),
                                       nullptr);
    if (!NT_SUCCESS(status) || thread == nullptr)
    {
        return FALSE;
    }

    process = PsGetThreadProcess(thread);
    pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
        PsGetProcessId(process)));

    if (pid == 0 || !NpDebugHideIsProtected(pid))
    {
        ObDereferenceObject(thread);
        return FALSE;                       // 非调试目标
    }

    //
    // 解析 DR7 使能槽（Lx/Gx）→ 转发为 NPT 断点/监视。
    //
    ULONG64 dr7 = ctx->Dr7;
    for (ULONG slot = 0; slot < 4; slot++)
    {
        ULONG64 drx;
        ULONG64 type;

        switch (slot)
        {
        case 0: drx = ctx->Dr0; break;
        case 1: drx = ctx->Dr1; break;
        case 2: drx = ctx->Dr2; break;
        default: drx = ctx->Dr3; break;
        }

        if ((dr7 & (1ULL << slot)) || (dr7 & (1ULL << (4 + slot))))
        {
            type = (dr7 >> (16 + slot * 4)) & 3;
            if (type == NPHV_DR_RW_EXECUTE)
            {
                //
                // 执行断点 → NPT 无痕断点（DEBUGGER 透传）。
                //
                NpBreakPointInstallEx(drx, NPHV_BP_FLAG_DEBUGGER,
                                      process, nullptr);
                NpHvLogPrint("[dbghide] hw-exec bp 0x%p -> NPT breakpoint\n",
                             reinterpret_cast<PVOID>(drx));
            }
            else if (type == NPHV_DR_RW_WRITE)
            {
                NpBreakPointInstallMonitor(drx, NPHV_MON_ACCESS_WRITE, nullptr);
            }
            else if (type == NPHV_DR_RW_READWRITE)
            {
                NpBreakPointInstallMonitor(drx,
                                           NPHV_MON_ACCESS_READ |
                                           NPHV_MON_ACCESS_WRITE,
                                           nullptr);
            }
            // IO 断点（RW=2）x64 不支持，忽略。
        }
    }

    ObDereferenceObject(thread);
    return FALSE;                           // 放行（调试器正常设上下文）
}

//
// ============================ LSTAR 分流包装（P3） ============================
//

static
VOID
NpDbgBuildHookCtx(
    _Out_ PHOOK_CALL_CONTEXT Ctx,
    _In_ ULONG_PTR Rcx,
    _In_ ULONG_PTR Rdx,
    _In_ ULONG_PTR R8,
    _In_ ULONG_PTR R9
    )
{
    RtlZeroMemory(Ctx, sizeof(*Ctx));
    Ctx->Rcx = Rcx;
    Ctx->Rdx = Rdx;
    Ctx->R8 = R8;
    Ctx->R9 = R9;
}

_Use_decl_annotations_
BOOLEAN
NpDebugHideQueryProcessInfoSplit(
    HANDLE ProcessHandle,
    ULONG InfoClass,
    PVOID Buffer,
    ULONG Length,
    PULONG_PTR OutStatus)
{
    HOOK_CALL_CONTEXT ctx;
    NpDbgBuildHookCtx(&ctx,
                      reinterpret_cast<ULONG_PTR>(ProcessHandle),
                      InfoClass,
                      reinterpret_cast<ULONG_PTR>(Buffer),
                      Length);
    BOOLEAN handled = NpDbgHideQueryProcessInfo(&ctx);
    if (OutStatus != nullptr)
    {
        *OutStatus = ctx.Rax;
    }
    return handled;
}

_Use_decl_annotations_
BOOLEAN
NpDebugHideReadVirtualMemorySplit(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    BOOLEAN DebuggerView,
    PSIZE_T BytesRead,
    PNTSTATUS OutStatus)
{
    //
    // DebuggerView 预留给"按调试器视图呈现"，实际实现在 RVM handler 里
    // （NpBreakPointOverlayCcForRead，按调用方是否为已附加调试器判断），
    // 本函数只是包装，最终走同一个 handler。
    //
    UNREFERENCED_PARAMETER(DebuggerView);

    HOOK_CALL_CONTEXT ctx;
    NpDbgBuildHookCtx(&ctx,
                      reinterpret_cast<ULONG_PTR>(ProcessHandle),
                      reinterpret_cast<ULONG_PTR>(BaseAddress),
                      reinterpret_cast<ULONG_PTR>(Buffer),
                      static_cast<ULONG_PTR>(Size));
    BOOLEAN handled = NpDbgHideReadVirtualMemory(&ctx);
    if (OutStatus != nullptr)
    {
        *OutStatus = static_cast<NTSTATUS>(ctx.Rax);
    }
    if (BytesRead != nullptr && NT_SUCCESS(static_cast<NTSTATUS>(ctx.Rax)))
    {
        *BytesRead = Size;
    }

    return handled;
}

_Use_decl_annotations_
BOOLEAN
NpDebugHideWriteVirtualMemorySplit(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    BOOLEAN DebuggerView,
    PSIZE_T BytesWritten,
    PNTSTATUS OutStatus)
{
    UNREFERENCED_PARAMETER(DebuggerView);
    HOOK_CALL_CONTEXT ctx;
    NpDbgBuildHookCtx(&ctx,
                      reinterpret_cast<ULONG_PTR>(ProcessHandle),
                      reinterpret_cast<ULONG_PTR>(BaseAddress),
                      reinterpret_cast<ULONG_PTR>(Buffer),
                      static_cast<ULONG_PTR>(Size));
    BOOLEAN handled = NpDbgHideWriteVirtualMemory(&ctx);
    if (OutStatus != nullptr)
    {
        *OutStatus = static_cast<NTSTATUS>(ctx.Rax);
    }
    if (BytesWritten != nullptr && NT_SUCCESS(static_cast<NTSTATUS>(ctx.Rax)))
    {
        *BytesWritten = Size;
    }
    return handled;
}

//
// ============================ Hook 安装 / 卸载 ============================
//

//
// ============================ Nt* 解析：导出表 + SSDT 兜底 ============================
//
// Windows 11 24H2+ 会把部分 Nt*/Zw* 移出内核导出表，导致
// MmGetSystemRoutineAddress 失败。SSDT 兜底：从 ntdll 的 syscall stub
// 提取系统调用号 → 定位 KiServiceTable → 索引出内核函数真实地址
// （不依赖导出表）。
//

static
PVOID
NpResolveRoutine(
    _In_ PCSTR Name
    )
{
    // P0 抽离：实现移至 NpSyscall.cpp。
    return NpSyscallResolveAddress(Name);
}

// SSDT 兜底解析（导出表移除 Nt*/Zw* 时的最后手段）。
// 移植自 NpProbe 验证版：双锚点 + 表特征扫描 + 模块基址语义。
static
PVOID
NpResolveViaSsdt(
    _In_ PCSTR NtName
    )
{
    // P0 抽离：完整 SSDT 解析（锚点/表特征/4B-8B）移至 NpSyscall.cpp。
    return NpSyscallResolveRoutine(NtName, nullptr);
}

// 导出表解析（MmGetSystemRoutineAddress 首选路径，已前置定义）。

// Nt* 函数解析（多策略：导出表 → Zw 别名 → SSDT）。
static
PVOID
NpGetNtRoutine(
    _In_ PCSTR Name
    )
{
    PVOID resolved;

    resolved = NpResolveRoutine(Name);
    if (resolved != nullptr)
    {
        return resolved;
    }

    //
    // 尝试 Zw 别名（"NtXxx" → "ZwXxx"，同地址；某些系统只保留其一）。
    //
    if (Name[0] == 'N' && Name[1] == 't')
    {
        char zwName[64];
        ULONG len = static_cast<ULONG>(strlen(Name));

        if (len + 1 < sizeof(zwName))
        {
            zwName[0] = 'Z';
            zwName[1] = 'w';
            RtlCopyMemory(zwName + 2, Name + 2, len - 1);   // 含结尾 NUL
            resolved = NpResolveRoutine(zwName);
            if (resolved != nullptr)
            {
                NpHvLogPrint("[dbghide] resolve '%s' -> Zw alias '%s'\n",
                             Name, zwName);
                return resolved;
            }
        }
    }

    //
    // 导出表全灭：SSDT 兜底（Win11 24H2+ 移除 Nt*/Zw* 导出的系统）。
    //
    resolved = NpResolveViaSsdt(Name);
    if (resolved != nullptr)
    {
        return resolved;
    }

    NpHvLogPrint("[dbghide] resolve '%s': not exported (Nt/Zw/ssdt)\n", Name);
    return nullptr;
}

_Use_decl_annotations_
NTSTATUS
NpDebugHideSetEnabled(
    BOOLEAN Enable)
{
    NTSTATUS status;
    ULONG hooked = 0;

    if (Enable != FALSE)
    {
        if (g_HideEnabled)
        {
            return STATUS_SUCCESS;          // 已开启
        }

        //
        // 新架构（LSTAR 接管）：syscall 语义由 NpLstarSyscallDispatch 分流
        // 完成（QIP/RVM/WVM/DAP/SCT），不再安装 NpHook 克隆重定位 Hook。
        // 这是"调试隐藏走 MSR/LSTAR 而非克隆页"的结构性切换。
        //
        if (NpLstarIsEnabled())
        {
            g_HideEnabled = TRUE;
            NpHvLogPrint("[dbghide] enabled via LSTAR (clone hooks skipped)\n");
            return STATUS_SUCCESS;
        }

        //
        // NtQueryInformationProcess：核心（调试检测伪造），必须成功。
        //
        status = NpHookInstallHook(reinterpret_cast<ULONG_PTR>(
                                       NpGetNtRoutine("NtQueryInformationProcess")),
                                   NpDbgHideQueryProcessInfo,
                                   &g_HookNtQIP);
        if (status == STATUS_ALREADY_REGISTERED)
        {
            // Page already owned by selfhide/prochide QSI hook (page-exclusive
            // design). Skip; QIP filtering degrades to LSTAR split if present.
            NpHvLogPrint("[dbghide] QIP page already hooked (shared with QSI), skipped\n");
        }
        else if (!NT_SUCCESS(status))
        {
            NpHvLogPrint("[dbghide] hook NtQueryInformationProcess failed: 0x%08x "
                         "(hv=%d)\n",
                         status, NpHvIsRunning() ? 1 : 0);
            return status;
        }
        hooked++; // ALREADY_REGISTERED tolerated

        //
        // 其余 Hook 严格模式：任一失败即整体失败（回滚已装 Hook 并报错）。
        // 干净系统上 Nt* 均应在导出表（Win11 24H2+ 可能移除 Nt 名，但
        // NpGetNtRoutine 的 Zw 别名兜底会解析到同一地址）。
        //
        #define NP_TRY_HOOK(RoutineName, Callback, Ptr)                        \
            do {                                                               \
                status = NpHookInstallHook(reinterpret_cast<ULONG_PTR>(        \
                                               NpGetNtRoutine(RoutineName)),   \
                                           Callback, Ptr);                     \
                if (status == STATUS_ALREADY_REGISTERED)                       \
                {                                                              \
                    /* Page already owned by another hook (page-exclusive). */ \
                    NpHvLogPrint("[dbghide] %s page already hooked, skipped\n",\
                                 RoutineName);                                 \
                }                                                              \
                else if (!NT_SUCCESS(status))                                  \
                {                                                              \
                    NpHvLogPrint("[dbghide] hook %s failed: 0x%08x\n",         \
                                 RoutineName, status);                         \
                    return status;                                             \
                }                                                              \
                hooked++;                                                      \
            } while (0)

        NP_TRY_HOOK("NtWriteVirtualMemory",
                    NpDbgHideWriteVirtualMemory,
                    &g_HookNtWVM);
        NP_TRY_HOOK("NtReadVirtualMemory",
                    NpDbgHideReadVirtualMemory,
                    &g_HookNtRVM);
        NP_TRY_HOOK("NtDebugActiveProcess",
                    NpDbgHideDebugActiveProcess,
                    &g_HookNtDAP);
        NP_TRY_HOOK("NtSetContextThread",
                    NpDbgHideSetContextThread,
                    &g_HookNtSCT);

        #undef NP_TRY_HOOK

        g_HideEnabled = TRUE;
        NpHvLogPrint("[dbghide] debug-hide enabled (%lu/%u hooks)\n",
                     hooked, 5);
        return STATUS_SUCCESS;
    }

    if (g_HookNtQIP != nullptr)
    {
        NpHookUninstallHook(g_HookNtQIP, FALSE);
        g_HookNtQIP = nullptr;
    }
    if (g_HookNtWVM != nullptr)
    {
        NpHookUninstallHook(g_HookNtWVM, FALSE);
        g_HookNtWVM = nullptr;
    }
    if (g_HookNtRVM != nullptr)
    {
        NpHookUninstallHook(g_HookNtRVM, FALSE);
        g_HookNtRVM = nullptr;
    }
    if (g_HookNtDAP != nullptr)
    {
        NpHookUninstallHook(g_HookNtDAP, FALSE);
        g_HookNtDAP = nullptr;
    }
    if (g_HookNtSCT != nullptr)
    {
        NpHookUninstallHook(g_HookNtSCT, FALSE);
        g_HookNtSCT = nullptr;
    }
    g_HideEnabled = FALSE;
    NpHvLogPrint("[dbghide] debug-hide disabled\n");
    return STATUS_SUCCESS;
}

//
// ============================ 生命周期 ============================
//

_Use_decl_annotations_
NTSTATUS
NpDebugHideInitialize(
    VOID)
{
    RtlZeroMemory(g_ProtectedPids, sizeof(g_ProtectedPids));
    RtlZeroMemory(g_ProtectedPebBase, sizeof(g_ProtectedPebBase));
    RtlZeroMemory(g_ProtectedDebuggerPid, sizeof(g_ProtectedDebuggerPid));
    KeInitializeSpinLock(&g_PidLock);
    KeInitializeEvent(&g_HideSweepEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_HcWorkEvent, NotificationEvent, FALSE);
    g_HideSweepExit = FALSE;
    g_HideSweepExited = FALSE;
    g_HideSweepThread = nullptr;
    {
        HANDLE hThread = nullptr;
        NTSTATUS st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
                                           nullptr, nullptr, nullptr,
                                           NpDebugHideSweepThread, nullptr);
        if (NT_SUCCESS(st)) g_HideSweepThread = hThread;
        else NpHvLogPrint("[dbghide] PEB sweep thread failed 0x%08x\n", st);
    }
    g_HideEnabled = FALSE;
    g_HookNtQIP = nullptr;
    g_HookNtWVM = nullptr;
    g_HookNtRVM = nullptr;
    g_HookNtDAP = nullptr;
    g_HookNtSCT = nullptr;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
NpDebugHideTeardown(
    VOID)
{
    //
    // 卸载 Hook（虚拟化在位时摘除更安全，但服务 Teardown 在去虚拟化后
    // 执行——此时 Hook 无执行者，立即释放安全）。
    //
    NpDebugHideSetEnabled(FALSE);
    if (g_HideSweepThread != nullptr)
    {
        KIRQL _irql = KeGetCurrentIrql();
        g_HideSweepExit = TRUE;
        KeSetEvent(&g_HideSweepEvent, IO_NO_INCREMENT, FALSE);
        if (_irql >= DISPATCH_LEVEL)
        {
            NpHvLogPrint("[dbghide] teardown: IRQL=%u >= DISPATCH, polling\n", _irql);
            for (ULONG _i = 0; _i < 40000 && !g_HideSweepExited; _i++)
            {
                KeStallExecutionProcessor(100);
            }
            if (!g_HideSweepExited)
            {
                NpHvLogPrint("[dbghide] WARNING: sweep thread did not exit in 4s, handle leaked (irql=%u)\n", _irql);
                return;
            }
        }
        else
        {
            ZwWaitForSingleObject(g_HideSweepThread, FALSE, NULL);
        }
        ZwClose(g_HideSweepThread);
        g_HideSweepThread = nullptr;
    }
    RtlZeroMemory(g_ProtectedPids, sizeof(g_ProtectedPids));
    RtlZeroMemory(g_ProtectedPebBase, sizeof(g_ProtectedPebBase));
    RtlZeroMemory(g_ProtectedDebuggerPid, sizeof(g_ProtectedDebuggerPid));
}
