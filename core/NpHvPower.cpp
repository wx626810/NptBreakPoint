/*!
    @file       NpHvPower.cpp

    @brief      core 层：电源回调（睡眠/唤醒时虚拟化状态失效需重建）。

    @details    使用经典 \Callback\PowerState 系统回调
    （ExCreateCallback + ExRegisterCallback）：
                - 睡眠（stateLock=TRUE） ：去虚拟化
                - 唤醒（stateLock=FALSE）：重新虚拟化 + 触发 PowerResume 事件
                （Hook 重新应用由订阅 NpHvEventPowerResume 的服务完成，
                  例如 services/NpHook）。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"

static PCALLBACK_OBJECT g_PowerCallbackObject = nullptr;
static PVOID g_PowerCallbackRegistration = nullptr;
static WORK_QUEUE_ITEM g_PowerWorkItem;         // DISPATCH 上下文延迟执行用
static volatile BOOLEAN g_PowerWorkPending = FALSE;
static volatile BOOLEAN g_PowerWorkRunning = FALSE;
static volatile BOOLEAN g_PowerPendingSleep = FALSE;   // 工作项待处理的动作

static
VOID
NptPowerWorkRoutine(
    _In_ PVOID Context
    )
{
    //
    // 工作项在 PASSIVE_LEVEL 执行：执行 DISPATCH 回调时延迟下来的
    // 电源状态转换（去虚拟化/重虚拟化）。
    // 若 PASSIVE 直接路径已先处理（清除了 pending），本工作项为 no-op
    // ——防止 wake 后重复去虚拟化把已恢复的虚拟化再次关闭。
    //
    UNREFERENCED_PARAMETER(Context);
    g_PowerWorkRunning = TRUE;
    if (!g_PowerWorkPending)
    {
        g_PowerWorkRunning = FALSE;
        return;                             // 已被 PASSIVE 直接路径处理
    }
    g_PowerWorkPending = FALSE;
    if (g_PowerPendingSleep)
    {
        g_PowerPendingSleep = FALSE;
        NpDebugPrint("Entering sleep (deferred), de-virtualizing...\n");
        NpHvDevirtualizeAllProcessors();
    }
    else
    {
        NTSTATUS status = NpHvVirtualizeAllProcessors();
        if (NT_SUCCESS(status))
        {
            NpHvFireEventPowerResume();
        }
        else
        {
            NpDebugPrint("Failed to re-virtualize after sleep: 0x%08x\n",
                         status);
        }
    }
}

static
VOID
NptPowerCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);

    //
    // Argument1 = PO_CB_SYSTEM_STATE_LOCK 表示系统电源状态即将改变。
    //
    if (Argument1 != reinterpret_cast<PVOID>(PO_CB_SYSTEM_STATE_LOCK))
    {
        return;
    }

    const BOOLEAN stateLock = static_cast<BOOLEAN>(reinterpret_cast<ULONG_PTR>(Argument2));
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        //
        // 电源回调可能运行在 DISPATCH_LEVEL，但 NpHvVirtualizeAllProcessors
        // 的亲和性切换/ExAllocatePool/SvLaunchVm 要求 PASSIVE_LEVEL——
        // 记录动作并排队工作项延迟处理。
        //
        if (!g_PowerWorkPending)
        {
            g_PowerPendingSleep = stateLock;
            g_PowerWorkPending = TRUE;
            ExQueueWorkItem(&g_PowerWorkItem, DelayedWorkQueue);
        }
        return;
    }

    if (stateLock != FALSE)
    {
        //
        // 即将睡眠：关闭虚拟化。
        // 清除 pending（若有 DISPATCH 排队的工作项，后续执行将 no-op）。
        //
        g_PowerWorkPending = FALSE;
        NpDebugPrint("Entering sleep, de-virtualizing...\n");
        NpHvDevirtualizeAllProcessors();
    }
    else
    {
        //
        // 唤醒：重新虚拟化并广播 PowerResume 事件。
        //
        g_PowerWorkPending = FALSE;         // 已由直接路径处理，工作项 no-op
        NpDebugPrint("Waking up, re-virtualizing...\n");
        NTSTATUS status = NpHvVirtualizeAllProcessors();
        if (NT_SUCCESS(status))
        {
            NpHvFireEventPowerResume();
        }
        else
        {
            NpDebugPrint("Failed to re-virtualize after sleep: 0x%08x\n", status);
        }
    }
    g_PowerWorkRunning = FALSE;
}

//
// 供 NpHv.cpp 触发的电源恢复事件（内部接口，避免循环 include）。
//
extern "C" VOID NpHvFireEventPowerResume(VOID);

_Use_decl_annotations_
NTSTATUS
NpHvRegisterPowerCallback(
    VOID)
{
    UNICODE_STRING callbackName;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;

    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&objectAttributes,
                               &callbackName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr,
                               nullptr);
    status = ExCreateCallback(&g_PowerCallbackObject,
                              &objectAttributes,
                              FALSE,      // 不创建（系统已有）
                              TRUE);      // 允许多个回调
    if (!NT_SUCCESS(status))
    {
        NpDebugPrint("Failed to create power callback object: 0x%08x\n", status);
        return status;
    }
    ExInitializeWorkItem(&g_PowerWorkItem, NptPowerWorkRoutine, nullptr);
    g_PowerWorkPending = FALSE;
    g_PowerCallbackRegistration = ExRegisterCallback(g_PowerCallbackObject,
                                                     NptPowerCallbackRoutine,
                                                     nullptr);
    if (g_PowerCallbackRegistration == nullptr)
    {
        NpDebugPrint("Failed to register power callback.\n");
        ObDereferenceObject(g_PowerCallbackObject);
        g_PowerCallbackObject = nullptr;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
NpHvUnregisterPowerCallback(
    VOID)
{
    // Block any deferred work that has not yet started.
    g_PowerWorkPending = FALSE;
    if (g_PowerCallbackRegistration != nullptr)
    {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = nullptr;
    }
    if (g_PowerCallbackObject != nullptr)
    {
        ObDereferenceObject(g_PowerCallbackObject);
        g_PowerCallbackObject = nullptr;
    }
    // If a deferred work item is already running, wait for it to finish
    // before the caller frees NPT/shared data (avoid UAF).
    for (ULONG _i = 0; _i < 40000 && g_PowerWorkRunning; _i++)
    {
        KeStallExecutionProcessor(100);
    }
}
