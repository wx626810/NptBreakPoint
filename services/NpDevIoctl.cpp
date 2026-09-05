/*!
    @file       NpDevIoctl.cpp

    @brief      services/NpDevIoctl：R3 管理通道（设备对象 + IOCTL 分发）。

    @details    功能（对应 NpIoctl.h 协议）：
                - QUERY_STATUS    查询 Hypervisor 状态 / Hook 计数
                - INSTALL_HOOK    R3 请求 Hook 某函数（动作模板：LogOnly/ReturnValue/PassThrough）
                - UNINSTALL_HOOK  按 HookId 卸载
                - UNINSTALL_ALL   卸载全部
                - DEVIRTUALIZE    R3 请求卸载 Hypervisor（含排空防 vmmcall #UD）
                - VMCALL          通用 vmmcall 透传（预留）

                安全设计：
                - R3 不传可执行代码；动作由内置回调模板实现
                - 目标地址必须位于内核地址空间（拒绝用户态地址注入）
                - HookId 表隐藏真实 HOOK_INFO 指针

                隐蔽性演进（未来）：设备伪装 / IOCTL 加密 / 影子通道 /
                全量 VMMCALL 管理通道 —— 见 NpIoctl.h 头注释与 docs。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpConfig.h"
#include "NpIoctl.h"
#include "NpHook.h"
#include "NpObf.h"
#include "NpBreakPoint.h"
#include "NpMemAccess.h"
#include "NpDebugHide.h"
#include "NpProcessHide.h"
#include "NpPseudoDbg.h"
#include "NpLstar.h"
#include "NpVHook.h"
#include "NpDataPatch.h"
#include "NpSyscall.h"
#include <intrin.h>

//
// ============================ 全局 ============================
//

static PDEVICE_OBJECT g_DeviceObject = nullptr;
static UNICODE_STRING g_DosDeviceName;
static wchar_t g_DecDev[32], g_DecDos[32];
PUNICODE_STRING NpDevGetDosDeviceName(void) { return &g_DosDeviceName; }
static PDRIVER_OBJECT g_DriverObject = nullptr;   // 由 NpDevRegisterDispatchers 保存，IoCreateDevice 必须非空

#define NP_MAX_IOCTL_HOOKS   64

//
// R3 Hook 句柄表：隐藏真实 PHOOK_INFO，且为回调提供 Action/ReturnValue。
// 条目在安装时写入（PASSIVE_LEVEL），回调并发只读（volatile 语义）。
//
typedef struct _NPHV_HOOK_ENTRY
{
    BOOLEAN InUse;
    ULONG HookId;
    PHOOK_INFO HookInfo;
    ULONG_PTR TargetFunction;
    ULONG Action;               // NPHV_HOOK_ACTION
    ULONG64 ReturnValue;
    PVOID CodePtr;              // CustomCode：R3 注入代码的可执行池地址
    SIZE_T CodeSize;            // CustomCode：缓冲大小（退休清零/释放用）
} NPHV_HOOK_ENTRY;

//
// 退休的 R3 注入代码缓冲。
// unhook 时不能立即释放 CodePtr——某 CPU 的跳板回调可能正在执行这段
// 机器码（HOOK_INFO 走 NpHook 退休链，唯独代码缓冲曾漏掉 → UAF 蓝屏）。
// 处理：先 RtlSecureZeroMemory 清零内容（不留机器码痕迹），再挂入本数组，
// 驱动卸载、虚拟化关闭后由 NpDevTeardown 统一释放（与 Hook 退休链同一
// 安全时点）。数组满则故意泄漏该缓冲并告警（泄漏远好于 UAF 崩溃）。
//
#define NP_MAX_RETIRED_CODE 128

typedef struct _NP_RETIRED_CODE
{
    PVOID Ptr;
    SIZE_T Size;
} NP_RETIRED_CODE;

static NP_RETIRED_CODE g_RetiredCode[NP_MAX_RETIRED_CODE];
static volatile LONG g_RetiredCodeCount = 0;

static
VOID
NpDevRetireCodePtr(
    _In_opt_ PVOID CodePtr,
    _In_ SIZE_T CodeSize)
{
    LONG idx;

    if (CodePtr == nullptr || CodeSize == 0)
    {
        return;
    }

    //
    // 立即清零内容：执行者若仍在跑，读到零而非被复用的池数据；
    // 同时抹掉机器码痕迹（隐蔽性）。
    //
    RtlSecureZeroMemory(CodePtr, CodeSize);

    idx = InterlockedIncrement(&g_RetiredCodeCount) - 1;
    if (idx >= NP_MAX_RETIRED_CODE)
    {
        NpHvLogPrint("[ioctl] retired-code array full, leak %zu bytes "
                     "(freed at reboot)\n", CodeSize);
        return;
    }
    g_RetiredCode[idx].Ptr = CodePtr;
    g_RetiredCode[idx].Size = CodeSize;
}

static
VOID
NpDevFreeRetiredCode(VOID)
{
    LONG count = g_RetiredCodeCount;
    if (count > NP_MAX_RETIRED_CODE)
    {
        count = NP_MAX_RETIRED_CODE;
    }
    for (LONG i = 0; i < count; i++)
    {
        if (g_RetiredCode[i].Ptr != nullptr)
        {
            ExFreePoolWithTag(g_RetiredCode[i].Ptr, 'dCoN');
            g_RetiredCode[i].Ptr = nullptr;
            g_RetiredCode[i].Size = 0;
        }
    }
    g_RetiredCodeCount = 0;
}

static NPHV_HOOK_ENTRY g_HookTable[NP_MAX_IOCTL_HOOKS];
static volatile ULONG g_NextHookId = 1;

//
// ============================ 回调模板 ============================
//
// 统一回调：按 Context->OriginalFunction 查表决定行为。
// 回调在 Guest 上下文执行（跳板内），必须极轻量、禁止重入目标函数。
//

static
BOOLEAN
NpDevHookCallback(
    _In_ PHOOK_CALL_CONTEXT Context
    )
{
    for (ULONG i = 0; i < NP_MAX_IOCTL_HOOKS; i++)
    {
        if (g_HookTable[i].InUse &&
            g_HookTable[i].TargetFunction == Context->OriginalFunction)
        {
            switch (g_HookTable[i].Action)
            {
            case NpHookActionLogOnly:
                NpHvLogPrint("[ioctl] call func=%p ret=%p rax=%p rcx=%p rdx=%p\n",
                             reinterpret_cast<PVOID>(Context->OriginalFunction),
                             reinterpret_cast<PVOID>(Context->ReturnAddress),
                             reinterpret_cast<PVOID>(Context->Rax),
                             reinterpret_cast<PVOID>(Context->Rcx),
                             reinterpret_cast<PVOID>(Context->Rdx));
                return FALSE;   // 放行

            case NpHookActionReturnValue:
                Context->Rax = g_HookTable[i].ReturnValue;
                return TRUE;    // 拦截：不执行原函数，直接返回

            case NpHookActionCustomCode:
                //
                // 完全信任 R3：直接执行注入的机器码（回调约定见 NpIoctl.h）。
                //
                return (reinterpret_cast<HOOK_CALLBACK>(g_HookTable[i].CodePtr))(Context);

            case NpHookActionPassThrough:
            default:
                return FALSE;   // 放行（仅统计计数）
            }
        }
    }
    return FALSE;
}

//
// ============================ IOCTL 处理 ============================
//

//
// 目标地址解析辅助：优先按导出函数名，其次按直接地址。
// 供 Hook / 断点 / 监视安装共用。
//
static
NTSTATUS
NpDevResolveTarget(
    _In_ const char* TargetName,
    _In_ uint64_t TargetAddress,
    _Out_ PULONG_PTR OutAddress
    )
{
    NTSTATUS status;

    if (TargetName[0] != '\0')
    {
        ANSI_STRING ansiName;
        UNICODE_STRING routineName;
        PVOID resolved;

        RtlInitAnsiString(&ansiName, TargetName);
        status = RtlAnsiStringToUnicodeString(&routineName, &ansiName, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        resolved = MmGetSystemRoutineAddress(&routineName);
        RtlFreeUnicodeString(&routineName);
        if (resolved == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        *OutAddress = reinterpret_cast<ULONG_PTR>(resolved);
        return STATUS_SUCCESS;
    }

    if (TargetAddress == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (TargetAddress < 0xFFFF000000000000ULL)
    {
        //
        // 拒绝用户态地址：不允许 R3 让内核处理用户态地址
        // （无痕断点/监视只面向内核代码/数据）。
        //
        return STATUS_INVALID_ADDRESS;
    }
    *OutAddress = static_cast<ULONG_PTR>(TargetAddress);
    return STATUS_SUCCESS;
}

//
// 无痕断点：安装
//
static
NTSTATUS
NpDevInstallBreakpoint(
    _In_ const NPHV_INSTALL_BREAKPOINT_REQUEST* Request,
    _Out_ PNPHV_INSTALL_BREAKPOINT_RESPONSE Response
    )
{
    NTSTATUS status;
    ULONG_PTR targetAddress;

    Response->BpId = 0;
    Response->Status = (uint32_t)STATUS_INVALID_PARAMETER;

    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }

    status = NpDevResolveTarget(Request->TargetName,
                                Request->TargetAddress,
                                &targetAddress);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = NpBreakPointInstall(targetAddress,
                                 Request->Flags,
                                 reinterpret_cast<PULONG>(&Response->BpId));
    Response->Status = status;
    return status;
}

//
// 无痕断点：卸载
//
static
NTSTATUS
NpDevUninstallBreakpoint(
    _In_ const NPHV_UNINSTALL_BREAKPOINT_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    return NpBreakPointUninstall(Request->BpId, TRUE);
}

//
// 无痕断点：列表查询
//
static
NTSTATUS
NpDevListBreakpoints(
    _Out_ PNPHV_LIST_BREAKPOINTS_RESPONSE Response
    )
{
    ULONG count = 0;

    NpBreakPointQuery(Response->Entries, NPHV_MAX_BREAKPOINTS, &count);
    Response->Count = count;
    Response->Total = NpBreakPointGetActiveCount();
    return STATUS_SUCCESS;
}

//
// 无痕断点：继续（HALT 模式）
//
static
NTSTATUS
NpDevContinueBreakpoint(
    _In_ const NPHV_CONTINUE_BREAKPOINT_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    return NpBreakPointContinue(Request->BpId);
}

//
// NPT 监视：安装
//
static
NTSTATUS
NpDevInstallMonitor(
    _In_ const NPHV_INSTALL_MONITOR_REQUEST* Request,
    _Out_ PNPHV_INSTALL_MONITOR_RESPONSE Response
    )
{
    NTSTATUS status;
    ULONG_PTR targetAddress;

    Response->MonitorId = 0;
    Response->Status = (uint32_t)STATUS_INVALID_PARAMETER;

    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }

    status = NpDevResolveTarget(Request->TargetName,
                                Request->TargetAddress,
                                &targetAddress);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = NpBreakPointInstallMonitor(targetAddress,
                                        Request->AccessType,
                                        reinterpret_cast<PULONG>(&Response->MonitorId));
    Response->Status = status;
    return status;
}

//
// NPT 监视：卸载
//
static
NTSTATUS
NpDevUninstallMonitor(
    _In_ const NPHV_UNINSTALL_MONITOR_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    return NpBreakPointUninstallMonitor(Request->MonitorId, TRUE);
}

//
// 无痕读内存
//
static
NTSTATUS
NpDevReadMemory(
    _In_ const NPHV_READ_MEMORY_REQUEST* Request,
    _Out_ PNPHV_READ_MEMORY_RESPONSE Response
    )
{
    NTSTATUS status;
    ULONG bytesRead = 0;

    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    if (Request->Size == 0 || Request->Size > NPHV_MAX_MEMORY_IO)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = NpMemAccessRead(Request->ProcessId,
                             static_cast<ULONG_PTR>(Request->VirtualAddress),
                             Response->Buffer,
                             Request->Size,
                             &bytesRead);
    Response->Status = status;
    Response->BytesRead = bytesRead;
    return status;
}

//
// DR 硬件断点虚拟化（drprobe）：开关
//
static
NTSTATUS
NpDevDrProbe(
    _In_ const NPHV_DRPROBE_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    return NpBreakPointSetDrProbe(Request->Enable != 0);
}

//
// DR 硬件断点虚拟化：状态查询（假 DR + 待转发断点）
//
static
NTSTATUS
NpDevDrState(
    _Out_ PNPHV_DRSTATE_RESPONSE Response
    )
{
    return NpBreakPointQueryDrState(Response);
}

//
// X64DBG 调试链路隐藏：开关
//
static
NTSTATUS
NpDevDebugHide(
    _In_ const NPHV_DEBUG_HIDE_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    NTSTATUS st = NpDebugHideSetEnabled(Request->Enable != 0);
    if (NT_SUCCESS(st)) {
        NTSTATUS pst = NpProcessHideSetEnabled(Request->Enable != 0);
        if (!NT_SUCCESS(pst))
        {
            NpHvLogPrint("[dbghide] hide=%u ok but prochide failed 0x%08x\n",
                         (ULONG)(Request->Enable != 0), pst);
        }
    }
    return st;
}

// (protect idempotent patch below)

//
// X64DBG 调试链路隐藏：注册受保护进程
//
static
NTSTATUS
NpDevDebugProtect(
    _In_ const NPHV_DEBUG_PROTECT_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    {
        NTSTATUS pst = NpDebugHideProtectProcess(Request->ProcessId,
                                                 Request->Protect != 0);
        // Idempotent: protecting an already-protected pid is success (183 fix).
        if (pst == STATUS_ALREADY_REGISTERED) pst = STATUS_SUCCESS;
        return pst;
    }
}

//
// X64DBG 调试链路隐藏：切换模式（白名单 / 黑名单）
//
static
NTSTATUS
NpDevDebugMode(
    _In_ const NPHV_DEBUG_MODE_REQUEST* Request
    )
{
    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    return NpDebugHideSetMode(Request->Mode);
}

static
NTSTATUS
NpDevQueryStatus(
    _Inout_ PNPHV_STATUS_RESPONSE Response
    )
{
    Response->Version = NPHV_PROTOCOL_VERSION;
    Response->HypervisorRunning = NpHvIsRunning() ? 1 : 0;
    Response->ProcessorCount = NpHvGetProcessorCount();
    Response->ActiveHookCount = NpHookGetActiveCount();
    Response->Flags = NpSelfHideIsEnabled() ? NPHV_FLAG_SELF_HIDE : 0;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NpDevInstallHook(
    _In_ const NPHV_INSTALL_HOOK_REQUEST* Request,
    _Out_ PNPHV_INSTALL_HOOK_RESPONSE Response
    )
{
    NTSTATUS status;
    PHOOK_INFO hookInfo;
    ULONG slot;
    ULONG_PTR targetAddress;

    Response->HookId = 0;
    Response->Status = (uint32_t)STATUS_INVALID_PARAMETER;

    if (Request->Version != NPHV_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }
    if (Request->Action >= NpHookActionMax)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 目标解析：优先按导出函数名（MmGetSystemRoutineAddress），
    // 其次按直接地址（必须是内核地址空间）。
    //
    if (Request->TargetName[0] != '\0')
    {
        ANSI_STRING ansiName;
        UNICODE_STRING routineName;
        PVOID resolved;

        RtlInitAnsiString(&ansiName, Request->TargetName);
        status = RtlAnsiStringToUnicodeString(&routineName, &ansiName, TRUE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        resolved = MmGetSystemRoutineAddress(&routineName);
        RtlFreeUnicodeString(&routineName);
        if (resolved == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        targetAddress = reinterpret_cast<ULONG_PTR>(resolved);
    }
    else
    {
        if (Request->TargetAddress == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (Request->TargetAddress < 0xFFFF000000000000ULL)
        {
            //
            // 拒绝用户态地址：不允许 R3 让内核 Hook 用户态地址
            // （防止把不可信目标交给内核回调）。
            //
            return STATUS_INVALID_ADDRESS;
        }
        targetAddress = Request->TargetAddress;
    }

    //
    // 分配 HookId 槽位。
    //
    slot = NP_MAX_IOCTL_HOOKS;
    for (ULONG i = 0; i < NP_MAX_IOCTL_HOOKS; i++)
    {
        if (!g_HookTable[i].InUse)
        {
            slot = i;
            break;
        }
    }
    if (slot == NP_MAX_IOCTL_HOOKS)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // CustomCode：把 R3 注入的机器码复制到可执行非分页池。
    // 完全信任 R3（拿到设备句柄即可注入内核代码）；代码必须
    // 位置无关且遵守 HOOK_CALLBACK 约定（见 NpIoctl.h）。
    //
    PVOID codePtr = nullptr;
    if (Request->Action == NpHookActionCustomCode)
    {
        if (Request->CodeSize == 0 || Request->CodeSize > NPHV_MAX_CODE_SIZE)
        {
            return STATUS_INVALID_PARAMETER;
        }
        codePtr = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                  Request->CodeSize,
                                  'dCoN');
        if (codePtr == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(codePtr, Request->CodeBytes, Request->CodeSize);
    }

    //
    // 安装（回调统一走 NpDevHookCallback，行为由表决定）。
    //
    status = NpHookInstallHook(targetAddress,
                               NpDevHookCallback,
                               &hookInfo);
    if (!NT_SUCCESS(status))
    {
        if (codePtr != nullptr)
        {
            ExFreePoolWithTag(codePtr, 'dCoN');
        }
        return status;
    }

    g_HookTable[slot].InUse = TRUE;
    g_HookTable[slot].HookId = g_NextHookId++;
    g_HookTable[slot].HookInfo = hookInfo;
    g_HookTable[slot].TargetFunction = targetAddress;
    g_HookTable[slot].Action = Request->Action;
    g_HookTable[slot].ReturnValue = Request->ReturnValue;
    g_HookTable[slot].CodePtr = codePtr;
    g_HookTable[slot].CodeSize =
        (Request->Action == NpHookActionCustomCode) ? Request->CodeSize : 0;

    Response->HookId = g_HookTable[slot].HookId;
    Response->Status = status;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NpDevUninstallHook(
    _In_ const NPHV_UNINSTALL_HOOK_REQUEST* Request
    )
{
    NTSTATUS status;
    PHOOK_INFO hookInfo = nullptr;

    status = STATUS_NOT_FOUND;

    for (ULONG i = 0; i < NP_MAX_IOCTL_HOOKS; i++)
    {
        if (g_HookTable[i].InUse && g_HookTable[i].HookId == Request->HookId)
        {
            hookInfo = g_HookTable[i].HookInfo;
            //
            // 不立即释放：跳板回调可能正在执行这段机器码。
            // 清零 + 挂退休数组，NpDevTeardown（虚拟化关闭后）统一释放。
            //
            NpDevRetireCodePtr(g_HookTable[i].CodePtr, g_HookTable[i].CodeSize);
            g_HookTable[i].InUse = FALSE;
            g_HookTable[i].HookInfo = nullptr;
            g_HookTable[i].TargetFunction = 0;
            g_HookTable[i].Action = NpHookActionMax;
            g_HookTable[i].ReturnValue = 0;
            g_HookTable[i].CodePtr = nullptr;
            g_HookTable[i].CodeSize = 0;
            status = STATUS_SUCCESS;
            break;
        }
    }

    if (hookInfo != nullptr)
    {
        //
        // 延迟释放（FreeResources=FALSE → 退休链表）：跳板/影子页可能
        // 正被其他 CPU 的 Hook 路径执行，立即释放会 use-after-free。
        // 退休资源在驱动卸载、虚拟化关闭后统一释放（NpHookFreeRetiredHooks）。
        //
        status = NpHookUninstallHook(hookInfo, FALSE);
    }
    return status;
}

static
NTSTATUS
NpDevUninstallAllHooks(
    VOID
    )
{
    //
    // 代码缓冲同样走退休（清零+延迟释放，防执行中 UAF）。
    //
    for (ULONG i = 0; i < NP_MAX_IOCTL_HOOKS; i++)
    {
        if (g_HookTable[i].CodePtr != nullptr)
        {
            NpDevRetireCodePtr(g_HookTable[i].CodePtr, g_HookTable[i].CodeSize);
        }
        g_HookTable[i].InUse = FALSE;
        g_HookTable[i].HookInfo = nullptr;
        g_HookTable[i].TargetFunction = 0;
        g_HookTable[i].Action = NpHookActionMax;
        g_HookTable[i].ReturnValue = 0;
        g_HookTable[i].CodePtr = nullptr;
        g_HookTable[i].CodeSize = 0;
    }
    return NpHookUninstallAllHooks(FALSE);  // 延迟释放（同上 UAF 防护）
}

static
NTSTATUS
NpDevDevirtualize(
    VOID
    )
{
    //
    // 先排空：等待仍在跳板/影子页上的存量线程跑完（虚拟化保持开启），
    // 避免去虚拟化后残留线程执行跳板尾部 vmmcall → #UD。
    //
    LARGE_INTEGER drainInterval;
    drainInterval.QuadPart = -NPTHOOK_UNLOAD_DRAIN_MS * 10000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &drainInterval);

    NpHvDevirtualizeAllProcessors();
    NpDebugPrint("IOCTL: hypervisor devirtualized by R3 request.\n");
    return STATUS_SUCCESS;
}

//
//
// ============================ 分发 ============================
//

static
NTSTATUS
NpDevDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_NPHV_QUERY_STATUS:
        if (outputLen >= sizeof(NPHV_STATUS_RESPONSE))
        {
            status = NpDevQueryStatus(static_cast<PNPHV_STATUS_RESPONSE>(buffer));
            info = sizeof(NPHV_STATUS_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_INSTALL_HOOK:
        //
        // BUFFERED 模式下 SystemBuffer = max(inLen, outLen)。
        // 响应写在 buffer+sizeof(REQUEST) 处，因此必须要求 outLen
        // 覆盖整个复合缓冲（request+response），否则内核越界写。
        //
        if (inputLen >= sizeof(NPHV_INSTALL_HOOK_REQUEST) &&
            outputLen >= sizeof(NPHV_INSTALL_HOOK_REQUEST) +
                         sizeof(NPHV_INSTALL_HOOK_RESPONSE))
        {
            PNPHV_INSTALL_HOOK_RESPONSE resp =
                reinterpret_cast<PNPHV_INSTALL_HOOK_RESPONSE>(
                    reinterpret_cast<PUCHAR>(buffer) + sizeof(NPHV_INSTALL_HOOK_REQUEST));
            status = NpDevInstallHook(
                static_cast<const NPHV_INSTALL_HOOK_REQUEST*>(buffer), resp);
            info = sizeof(NPHV_INSTALL_HOOK_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_UNINSTALL_HOOK:
        if (inputLen >= sizeof(NPHV_UNINSTALL_HOOK_REQUEST))
        {
            status = NpDevUninstallHook(
                static_cast<const NPHV_UNINSTALL_HOOK_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_UNINSTALL_ALL:
        status = NpDevUninstallAllHooks();
        info = 0;
        break;

    case IOCTL_NPHV_DEVIRTUALIZE:
        status = NpDevDevirtualize();
        info = 0;
        break;

    case IOCTL_NPHV_VMCALL:
        //
        // 预留：通用 vmmcall 透传通道（未来扩展 HV 特权操作）。
        //
        NpDebugPrint("IOCTL_NPHV_VMCALL: reserved channel (function=0x%x)\n",
                     inputLen >= sizeof(NPHV_VMCALL_REQUEST)
                         ? static_cast<const NPHV_VMCALL_REQUEST*>(buffer)->FunctionCode
                         : 0);
        status = STATUS_NOT_IMPLEMENTED;
        info = 0;
        break;

    case IOCTL_NPHV_INSTALL_BREAKPOINT:
        if (inputLen >= sizeof(NPHV_INSTALL_BREAKPOINT_REQUEST) &&
            outputLen >= sizeof(NPHV_INSTALL_BREAKPOINT_REQUEST) +
                         sizeof(NPHV_INSTALL_BREAKPOINT_RESPONSE))
        {
            PNPHV_INSTALL_BREAKPOINT_RESPONSE resp =
                reinterpret_cast<PNPHV_INSTALL_BREAKPOINT_RESPONSE>(
                    reinterpret_cast<PUCHAR>(buffer) + sizeof(NPHV_INSTALL_BREAKPOINT_REQUEST));
            status = NpDevInstallBreakpoint(
                static_cast<const NPHV_INSTALL_BREAKPOINT_REQUEST*>(buffer), resp);
            info = sizeof(NPHV_INSTALL_BREAKPOINT_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_UNINSTALL_BREAKPOINT:
        if (inputLen >= sizeof(NPHV_UNINSTALL_BREAKPOINT_REQUEST))
        {
            status = NpDevUninstallBreakpoint(
                static_cast<const NPHV_UNINSTALL_BREAKPOINT_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_LIST_BREAKPOINTS:
        if (outputLen >= sizeof(NPHV_LIST_BREAKPOINTS_RESPONSE))
        {
            status = NpDevListBreakpoints(
                static_cast<PNPHV_LIST_BREAKPOINTS_RESPONSE>(buffer));
            info = sizeof(NPHV_LIST_BREAKPOINTS_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_CONTINUE_BREAKPOINT:
        if (inputLen >= sizeof(NPHV_CONTINUE_BREAKPOINT_REQUEST))
        {
            status = NpDevContinueBreakpoint(
                static_cast<const NPHV_CONTINUE_BREAKPOINT_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_INSTALL_MONITOR:
        if (inputLen >= sizeof(NPHV_INSTALL_MONITOR_REQUEST) &&
            outputLen >= sizeof(NPHV_INSTALL_MONITOR_REQUEST) +
                         sizeof(NPHV_INSTALL_MONITOR_RESPONSE))
        {
            PNPHV_INSTALL_MONITOR_RESPONSE resp =
                reinterpret_cast<PNPHV_INSTALL_MONITOR_RESPONSE>(
                    reinterpret_cast<PUCHAR>(buffer) + sizeof(NPHV_INSTALL_MONITOR_REQUEST));
            status = NpDevInstallMonitor(
                static_cast<const NPHV_INSTALL_MONITOR_REQUEST*>(buffer), resp);
            info = sizeof(NPHV_INSTALL_MONITOR_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_UNINSTALL_MONITOR:
        if (inputLen >= sizeof(NPHV_UNINSTALL_MONITOR_REQUEST))
        {
            status = NpDevUninstallMonitor(
                static_cast<const NPHV_UNINSTALL_MONITOR_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_READ_MEMORY:
        if (inputLen >= sizeof(NPHV_READ_MEMORY_REQUEST) &&
            outputLen >= sizeof(NPHV_READ_MEMORY_REQUEST) +
                         sizeof(NPHV_READ_MEMORY_RESPONSE))
        {
            PNPHV_READ_MEMORY_RESPONSE resp =
                reinterpret_cast<PNPHV_READ_MEMORY_RESPONSE>(
                    reinterpret_cast<PUCHAR>(buffer) + sizeof(NPHV_READ_MEMORY_REQUEST));
            status = NpDevReadMemory(
                static_cast<const NPHV_READ_MEMORY_REQUEST*>(buffer), resp);
            info = sizeof(NPHV_READ_MEMORY_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_DRPROBE:
        if (inputLen >= sizeof(NPHV_DRPROBE_REQUEST))
        {
            status = NpDevDrProbe(
                static_cast<const NPHV_DRPROBE_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_DRSTATE:
        if (outputLen >= sizeof(NPHV_DRSTATE_RESPONSE))
        {
            status = NpDevDrState(static_cast<PNPHV_DRSTATE_RESPONSE>(buffer));
            info = sizeof(NPHV_DRSTATE_RESPONSE);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_DEBUG_HIDE:
        if (inputLen >= sizeof(NPHV_DEBUG_HIDE_REQUEST))
        {
            NpLstarRefresh();               // 用户进程上下文：补齐 syscall 表
            status = NpDevDebugHide(
                static_cast<const NPHV_DEBUG_HIDE_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_DEBUG_PROTECT:
        if (inputLen >= sizeof(NPHV_DEBUG_PROTECT_REQUEST))
        {
            status = NpDevDebugProtect(
                static_cast<const NPHV_DEBUG_PROTECT_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_DEBUG_MODE:
        if (inputLen >= sizeof(NPHV_DEBUG_MODE_REQUEST))
        {
            status = NpDevDebugMode(
                static_cast<const NPHV_DEBUG_MODE_REQUEST*>(buffer));
            info = 0;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_NPHV_PROCESS_HIDE:
        if (inputLen >= sizeof(NPHV_PROCESS_HIDE_REQUEST))
        {
            auto req = static_cast<const NPHV_PROCESS_HIDE_REQUEST*>(buffer);
            if (req->Version != NPHV_PROTOCOL_VERSION) status = STATUS_REVISION_MISMATCH;
            else {
                NpLstarRefresh();
                status = NpProcessHideSetEnabled(req->Enable ? TRUE : FALSE);
            }
            info = 0;
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_NPHV_PROCESS_HIDE_ADD:
        if (inputLen >= sizeof(NPHV_PROCESS_HIDE_NAME_REQUEST))
        {
            auto req = static_cast<const NPHV_PROCESS_HIDE_NAME_REQUEST*>(buffer);
            if (req->Version != NPHV_PROTOCOL_VERSION) status = STATUS_REVISION_MISMATCH;
            else status = NpProcessHideAdd(req->Name);
            info = 0;
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_NPHV_PROCESS_HIDE_REMOVE:
        if (inputLen >= sizeof(NPHV_PROCESS_HIDE_NAME_REQUEST))
        {
            auto req = static_cast<const NPHV_PROCESS_HIDE_NAME_REQUEST*>(buffer);
            if (req->Version != NPHV_PROTOCOL_VERSION) status = STATUS_REVISION_MISMATCH;
            else status = NpProcessHideRemove(req->Name);
            info = 0;
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_NPHV_PROCESS_HIDE_CLEAR:
        NpProcessHideClearAll();
        status = STATUS_SUCCESS; info=0; break;
    case IOCTL_NPHV_PROCESS_WATCH_ADD:
        if (inputLen >= sizeof(NPHV_PROCESS_HIDE_NAME_REQUEST))
        {
            auto req = static_cast<const NPHV_PROCESS_HIDE_NAME_REQUEST*>(buffer);
            if (req->Version != NPHV_PROTOCOL_VERSION) status = STATUS_REVISION_MISMATCH;
            else status = NpProcessWatchAdd(req->Name);
            info = 0;
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_NPHV_PROCESS_WATCH_REMOVE:
        if (inputLen >= sizeof(NPHV_PROCESS_HIDE_NAME_REQUEST))
        {
            auto req = static_cast<const NPHV_PROCESS_HIDE_NAME_REQUEST*>(buffer);
            if (req->Version != NPHV_PROTOCOL_VERSION) status = STATUS_REVISION_MISMATCH;
            else status = NpProcessWatchRemove(req->Name);
            info = 0;
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_NPHV_PROCESS_WATCH_LIST:
        if (outputLen >= sizeof(NPHV_PROCESS_HIDE_LIST_RESPONSE))
        {
            auto resp = static_cast<PNPHV_PROCESS_HIDE_LIST_RESPONSE>(buffer);
            RtlZeroMemory(resp, sizeof(NPHV_PROCESS_HIDE_LIST_RESPONSE));
            // Enabled 复用为"prochide 总开关当前状态"，便于 R3 一并显示。
            resp->Enabled = NpProcessHideIsEnabled() ? 1 : 0;
            resp->Count = NpProcessWatchCopyNames(&resp->Names[0][0], 16);
            status = STATUS_SUCCESS; info = sizeof(NPHV_PROCESS_HIDE_LIST_RESPONSE);
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;
    case IOCTL_NPHV_PROCESS_HIDE_LIST:
        if (outputLen >= sizeof(NPHV_PROCESS_HIDE_LIST_RESPONSE))
        {
            auto resp = static_cast<PNPHV_PROCESS_HIDE_LIST_RESPONSE>(buffer);
            RtlZeroMemory(resp, sizeof(NPHV_PROCESS_HIDE_LIST_RESPONSE));
            resp->Enabled = NpProcessHideIsEnabled() ? 1 : 0;
            // 拷贝已注册隐藏名；Count 以实际拷贝数为准（与 Names 一致）。
            resp->Count = NpProcessHideCopyNames(&resp->Names[0][0], 16);
            status = STATUS_SUCCESS; info = sizeof(NPHV_PROCESS_HIDE_LIST_RESPONSE);
        } else status = STATUS_BUFFER_TOO_SMALL;
        break;

    case IOCTL_NPHV_PATCH_INSTALL:
        status = STATUS_NOT_SUPPORTED;      // 补丁视图已移除
        break;
    case IOCTL_NPHV_PATCH_REMOVE:
        status = STATUS_NOT_SUPPORTED;      // 补丁视图已移除
        break;
    case IOCTL_NPHV_PSEUDO_ATTACH:
        NpLstarRefresh();
        if(inputLen >= sizeof(NPHV_PSEUDO_ATTACH_REQUEST) && outputLen >= sizeof(NPHV_PSEUDO_ATTACH_RESPONSE)){ auto req=(NPHV_PSEUDO_ATTACH_REQUEST*)buffer; auto resp=(NPHV_PSEUDO_ATTACH_RESPONSE*)buffer; if(req->Version!=NPHV_PROTOCOL_VERSION) status=STATUS_REVISION_MISMATCH; else { ULONG sid=0; status=NpPseudoDbgCreateSession(req->TargetPid, (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), &sid); if(NT_SUCCESS(status)){ NpDebugHideProtectProcess(req->TargetPid, TRUE); NpDebugHideNoteDebugger(req->TargetPid, (ULONG)(ULONG_PTR)PsGetCurrentProcessId()); NpBreakPointSetDrProbe(TRUE); NpPseudoDbgSnapshot(req->TargetPid, (ULONG)(ULONG_PTR)PsGetCurrentProcessId()); } resp->SessionId=sid; resp->Status=status; info=sizeof(NPHV_PSEUDO_ATTACH_RESPONSE); } } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_PSEUDO_WAIT:
        if(inputLen >= sizeof(NPHV_PSEUDO_DETACH_REQUEST)){
            auto req=(NPHV_PSEUDO_DETACH_REQUEST*)buffer;
            if(req->Version!=NPHV_PROTOCOL_VERSION) status=STATUS_REVISION_MISMATCH;
            else { status = NpPseudoDbgWaitReadyById(req->SessionId); info=0; }
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_PSEUDO_CONTINUE:
        if(inputLen >= sizeof(NPHV_PSEUDO_DETACH_REQUEST)){
            auto req=(NPHV_PSEUDO_DETACH_REQUEST*)buffer;
            if(req->Version!=NPHV_PROTOCOL_VERSION) status=STATUS_REVISION_MISMATCH;
            else { status = NpPseudoDbgContinueById(req->SessionId, 0); info=0; }
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_PSEUDO_DETACH:
        if(inputLen >= sizeof(NPHV_PSEUDO_DETACH_REQUEST)){
            auto req=(NPHV_PSEUDO_DETACH_REQUEST*)buffer;
            if(req->Version!=NPHV_PROTOCOL_VERSION) status=STATUS_REVISION_MISMATCH;
            else { status = NpPseudoDbgRemoveSession(req->SessionId); info=0; }
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_PSEUDO_STATUS:
        if(outputLen >= sizeof(NPHV_PSEUDO_STATUS_RESPONSE)){
            auto resp=(NPHV_PSEUDO_STATUS_RESPONSE*)buffer;
            RtlZeroMemory(resp, sizeof(*resp));
            resp->Status = STATUS_SUCCESS;
            resp->Count = 0;
            for (ULONG sid = 1; sid < 0x10000 && resp->Count < NPHV_PSEUDO_MAX_SESSIONS_CTL; sid++)
            {
                ULONG tpid = 0, dpid = 0, evc = 0;
                if (NpPseudoDbgGetSessionInfo(sid, &tpid, &dpid, &evc))
                {
                    resp->Entries[resp->Count].SessionId = sid;
                    resp->Entries[resp->Count].TargetPid = tpid;
                    resp->Entries[resp->Count].DebuggerPid = dpid;
                    resp->Entries[resp->Count].EventCount = evc;
                    resp->Count++;
                }
            }
            status = STATUS_SUCCESS;
            info = sizeof(NPHV_PSEUDO_STATUS_RESPONSE);
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_LSTAR_STATUS:
        if(outputLen >= sizeof(NPHV_LSTAR_STATUS_RESPONSE)){ auto r=(NPHV_LSTAR_STATUS_RESPONSE*)buffer; RtlZeroMemory(r, sizeof(*r)); r->OrigLstar=(uint64_t)NpLstarGetOriginalKiSystemCall64(); r->Trampoline=(uint64_t)NpLstarGetTrampolineVa(); r->Hooked = (NpLstarIsEnabled() && r->Trampoline)?1:0; r->InterceptCount=NpLstarGetInterceptCount(); status=STATUS_SUCCESS; info=sizeof(NPHV_LSTAR_STATUS_RESPONSE); } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_VHOOK_INSTALL:
    case IOCTL_NPHV_VHOOK_REMOVE:
    case IOCTL_NPHV_VHOOK_LIST:
        status = STATUS_NOT_SUPPORTED;      // VHOOK 已移除
        break;
    case IOCTL_NPHV_DATA_PATCH_INSTALL:
    case IOCTL_NPHV_DATA_PATCH_REMOVE:
    case IOCTL_NPHV_DATA_PATCH_LIST:
        status = STATUS_NOT_SUPPORTED;      // 数据补丁已移除
        break;
    case IOCTL_NPHV_SYSCALL_PRECHECK:
        NpLstarRefresh();
        if(outputLen >= sizeof(NPHV_SYSCALL_PRECHECK_RESPONSE)){
            auto resp=(NPHV_SYSCALL_PRECHECK_RESPONSE*)buffer;
            RtlZeroMemory(resp, sizeof(*resp));
            NPSYSCALL_PRECHECK_RESULT r;
            status = NpSyscallPrecheck(&r);
                resp->Status = (uint32_t)status;
            resp->Count = r.Count;
            resp->AllPassed = r.AllPassed ? 1 : 0;
            resp->TableCrossChecked = r.TableCrossChecked ? 1 : 0;
            resp->ServiceTable = (uint64_t)r.ServiceTable;
            resp->ModuleBase = (uint64_t)r.ModuleBase;
            resp->Is4B = r.Is4B ? 1 : 0;
            for (ULONG i = 0; i < r.Count && i < NPHV_SYSCALL_PRECHECK_COUNT; i++)
            {
                RtlCopyMemory(resp->Entries[i].Name, r.Entries[i].Name, 47);
                resp->Entries[i].Address = (uint64_t)(ULONG_PTR)r.Entries[i].Address;
                resp->Entries[i].Syscall = r.Entries[i].Syscall;
                resp->Entries[i].IsSyscall = r.Entries[i].IsSyscall ? 1 : 0;
                resp->Entries[i].Resolved = r.Entries[i].Resolved ? 1 : 0;
            }
            info = sizeof(NPHV_SYSCALL_PRECHECK_RESPONSE);
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_NPHV_PATCH_LIST:
        status = STATUS_NOT_SUPPORTED;      // 补丁视图已移除
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static
NTSTATUS
NpDevDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// ============================ 服务生命周期 ============================
//

_Use_decl_annotations_
extern "C"
NTSTATUS
NpDevInitialize(
    VOID)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;

    // Random device names: \Device\NpHv_XXXXXXXX + \DosDevices\NpHv_XXXXXXXX
    {
        const unsigned short encDev[] = {0x0006,0x001F,0x003D,0x002F,0x0037,0x003C,0x0039,0x0001,0x001C,0x0023,0x0018,0x0027};
        const unsigned short encDos[] = {0x0006,0x001F,0x0037,0x002A,0x001A,0x003A,0x002A,0x0034,0x0031,0x0036,0x0023,0x000D,0x0018,0x0027,0x001C,0x0023};
        // decrypt base prefix \Device\NpHv and \DosDevices\NpHv to globals
        for(int i=0;i<12;i++) g_DecDev[i]=(wchar_t)(encDev[i] ^ 0x5A ^ (i & 0xFF));
        for(int i=0;i<16;i++) g_DecDos[i]=(wchar_t)(encDos[i] ^ 0x5A ^ (i & 0xFF));
        g_DecDev[12]=0; g_DecDos[16]=0;
        // Append random suffix _XXXXXXXX (8 hex) for stealth
        {
            LARGE_INTEGER tick; KeQueryTickCount(&tick); ULONG rnd = (ULONG)tick.QuadPart ^ (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            rnd ^= RtlRandomEx(&rnd);
            wchar_t suffix[9];
            // Use RtlStringCchPrintfW if available, else manual hex
            for(int i=7;i>=0;i--){ suffix[i]= L"0123456789ABCDEF"[rnd & 0xF]; rnd >>=4; }
            suffix[8]=0;
            // g_DecDev = \Device\NpHv + _ + suffix
            g_DecDev[12]=L'_';
            for(int i=0;i<8;i++) g_DecDev[13+i]=suffix[i];
            g_DecDev[21]=0;
            g_DecDos[16]=L'_';
            for(int i=0;i<8;i++) g_DecDos[17+i]=suffix[i];
            g_DecDos[25]=0;
        }
        RtlInitUnicodeString(&deviceName, g_DecDev);
        RtlInitUnicodeString(&g_DosDeviceName, g_DecDos);
        // use immediately before stack cleared
        // IoCreateDevice will copy the string
    }

    status = IoCreateDevice(g_DriverObject,
                            sizeof(ULONG_PTR),       // extension
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

#if NPT_NO_DEVICE
    status = STATUS_SUCCESS;
#else
    status = IoCreateSymbolicLink(&g_DosDeviceName, &deviceName);
#endif
    if (!NT_SUCCESS(status))
    {
#if !NPT_NO_DEVICE
        IoDeleteDevice(g_DeviceObject);
#endif
        g_DeviceObject = nullptr;
        return status;
    }

    g_DeviceObject->Flags |= DO_DIRECT_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlZeroMemory(g_HookTable, sizeof(g_HookTable));
    RtlZeroMemory(g_RetiredCode, sizeof(g_RetiredCode));
    g_RetiredCodeCount = 0;
    g_NextHookId = 1;

    NpDebugPrint("IOCTL device \\Device\\NpHv created.\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
extern "C"
VOID
NpDevTeardown(
    VOID)
{
    //
    // 释放退休的 R3 注入代码池（驱动卸载、虚拟化已关闭后调用：
    // 此刻不可能再有回调在执行机器码，绝对安全）。
    //
    NpDevFreeRetiredCode();

    for (ULONG i = 0; i < NP_MAX_IOCTL_HOOKS; i++)
    {
        if (g_HookTable[i].CodePtr != nullptr)
        {
            ExFreePoolWithTag(g_HookTable[i].CodePtr, 'dCoN');
            g_HookTable[i].CodePtr = nullptr;
        }
    }

    if (g_DeviceObject != nullptr)
    {
#if !NPT_NO_DEVICE
        IoDeleteSymbolicLink(&g_DosDeviceName);
#endif
#if !NPT_NO_DEVICE
        IoDeleteDevice(g_DeviceObject);
#endif
        g_DeviceObject = nullptr;
    }
}

//
// 分发器注册（组装层调用一次）。
//
_Use_decl_annotations_
extern "C"
VOID
NpDevRegisterDispatchers(
    PDRIVER_OBJECT DriverObject)
{
    g_DriverObject = DriverObject;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NpDevDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NpDevDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NpDevDispatchDeviceControl;
}
