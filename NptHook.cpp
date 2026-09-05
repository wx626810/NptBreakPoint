/*!
    @file       NptHook.cpp

    @brief      驱动组装层（薄壳）：DriverEntry / Unload。

    @details    本文件只做"组装"：
                1. 服务注册表按序 Init（platform → services → core 依赖顺序）
                2. 启动虚拟化
                3. 虚拟化完成后安装业务 Hook（demo）
                4. Unload 按逆序 Teardown

                新增功能模块的接入方式：
                - 在 services/demo 下新建 .cpp，导出 Init/Teardown
                - 在下方服务注册表中登记
                不要在本文件写业务逻辑。

                分层依赖（单向）：
                    demo → services → core → platform
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"

//
// ============================ 服务注册表 ============================
//
// Init 按数组顺序调用（先注册先初始化）；Teardown 按逆序调用。
// PostVirtualize 阶段在虚拟化完成后执行（可安装 Hook）。
//

typedef struct _NP_SERVICE
{
    const char* Name;
    NTSTATUS(*Init)(VOID);
    VOID(*Teardown)(VOID);
    BOOLEAN PostVirtualize;     // TRUE = 虚拟化完成后才 Init
} NP_SERVICE;

// services/NpLog
EXTERN_C NTSTATUS NpLogInitialize(VOID);
EXTERN_C VOID NpLogTeardown(VOID);
EXTERN_C void NpLstarDisableForUnload(void);

// services/NpHook
EXTERN_C VOID NpHookManagerInitialize(VOID);

// services/NpBreakPoint（无痕断点 / NPT 监视）
EXTERN_C NTSTATUS NpBreakPointInitialize(VOID);
EXTERN_C VOID NpBreakPointTeardown(VOID);
EXTERN_C NTSTATUS NpBreakPointUninstallAll(BOOLEAN FreeResources);
EXTERN_C NTSTATUS NpBreakPointFreeRetired(VOID);

// services/NpDebugHide（X64DBG 调试链路隐藏）
EXTERN_C NTSTATUS NpProcessHideInitialize(VOID);
EXTERN_C VOID NpProcessHideTeardown(VOID);
EXTERN_C NTSTATUS NpDebugHideInitialize(VOID);
EXTERN_C NTSTATUS NpPseudoDbgInitialize(VOID);
EXTERN_C void NpPseudoDbgTeardown(VOID);
EXTERN_C NTSTATUS NpLstarInitialize(VOID);
EXTERN_C void NpLstarTeardown(VOID);
EXTERN_C NTSTATUS NpLstarPreInitialize(VOID);
EXTERN_C NTSTATUS NpSyscallInitialize(VOID);
EXTERN_C void NpSyscallTeardown(void);
EXTERN_C VOID NpDebugHideTeardown(VOID);

// services/NpDevIoctl（R3 管理通道）
EXTERN_C NTSTATUS NpDevInitialize(VOID);
EXTERN_C VOID NpDevTeardown(VOID);
EXTERN_C VOID NpDevRegisterDispatchers(PDRIVER_OBJECT DriverObject);

// demo/DemoHook
EXTERN_C NTSTATUS NpDemoHooksInstall(VOID);
EXTERN_C VOID NpDemoHooksTeardown(VOID);

static const NP_SERVICE g_Services[] =
{
    // 虚拟化前初始化
    { "syscall",    NpSyscallInitialize,   NpSyscallTeardown,     FALSE },
    { "lstarpre",   NpLstarPreInitialize,  nullptr,               FALSE },
    { "log",        NpLogInitialize,       NpLogTeardown,         FALSE },
    { "hookmgr",    nullptr,               nullptr,               FALSE },
    { "devioctl",   NpDevInitialize,       NpDevTeardown,         FALSE },
    // 虚拟化后安装业务功能
    { "breakpoint", NpBreakPointInitialize, NpBreakPointTeardown, TRUE  },
    { "pseudo",   NpPseudoDbgInitialize, NpPseudoDbgTeardown, TRUE  },
    { "lstar",      NpLstarInitialize,     NpLstarTeardown,       TRUE  },
    { "dbghide",    NpDebugHideInitialize,  NpDebugHideTeardown,  TRUE  },
    { "prochide",   NpProcessHideInitialize, NpProcessHideTeardown, TRUE  },
#if NPTHOOK_INSTALL_DEMO_HOOKS
    { "demo",       NpDemoHooksInstall,    NpDemoHooksTeardown,   TRUE  },
#endif
};

#define NP_SERVICE_COUNT (sizeof(g_Services) / sizeof(g_Services[0]))

//
// ============================ 卸载 ============================
//

static
VOID
NptDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    NpDebugPrint("NptHook unloading...\n");

    //
    // 0. 链回驱动模块列表项（自隐藏开启时）。
    //    必须在任何清理之前：系统卸载流程依赖模块链完整。
    //
    NpSelfHideRestore();

    //
    // 1. 摘除全部 Hook 并恢复恒等映射（虚拟化仍在位时完成）。
    //    不释放内存（FreeResources=FALSE）：跳板/影子页可能正被其他
    //    CPU 上的线程执行，立即释放会 use-after-free 死机。
    //
    NpHookUninstallAllHooks(FALSE);
    NpHvLogPrint("[unload] step1 irql=%u\n", KeGetCurrentIrql());

    //
    // 1b. 摘除全部无痕断点/监视并恢复恒等映射（同上，延迟释放）。
    //
    NpBreakPointUninstallAll(FALSE);
    NpHvLogPrint("[unload] step1b irql=%u\n", KeGetCurrentIrql());

    //
    // 1c. 摘除全部用户态隐匿补丁视图并恢复恒等映射（虚拟化仍在位时）。
    //     资源转入退休链，随步骤 7 统一释放。
    //
    // 补丁视图已移除（2026-08-28）。
    NpHvLogPrint("[unload] step1c irql=%u\n", KeGetCurrentIrql());

    //
    // 2. 停止影子页复位线程。
    //
    NpHvStopShadowResetThread();
    NpHvLogPrint("[unload] step2 irql=%u\n", KeGetCurrentIrql());

    //
    // 2b. LSTAR early gate: prevent new syscall trampoline entries
    //     after Devirtualize frees the trampoline (R3).
    //
    NpLstarDisableForUnload();
    NpHvLogPrint("[unload] step2b irql=%u\n", KeGetCurrentIrql());

    //
    // 3. 停止日志落盘线程。
    //
    NpLogTeardown();

    //
    // 4. 排空窗口：等待仍在跳板/影子页上的存量线程执行完毕。
    //    Hook 已全部摘除（NPF 不再重定向跳板），这里只需等正在执行的
    //    跳板跑完——回调仅微秒级，200ms 足够。必须等虚拟化仍开启
    //    （跳板尾部 vmmcall 才能正常复位），否则残留线程恢复执行时
    //    vmmcall → #UD 死机。
    //
    {
        LARGE_INTEGER drainInterval;
        drainInterval.QuadPart = -NPTHOOK_UNLOAD_DRAIN_MS * 10000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &drainInterval);
    }

    //
    // 5. 去虚拟化全部处理器。此刻无任何线程在跳板/影子页上。
    //
    NpHvDevirtualizeAllProcessors();

    //
    // 6. 注销电源回调。
    //
    NpHvUnregisterPowerCallback();

    //
    // 7. 释放退休 Hook / 断点 / 监视资源（虚拟化已关闭，绝对安全）。
    //
    NpHookFreeRetiredHooks();
    NpBreakPointFreeRetired();
    // 补丁视图已移除（2026-08-28）。

    //
    // 8. 服务 Teardown（逆序）。
    //
    for (LONG i = static_cast<LONG>(NP_SERVICE_COUNT) - 1; i >= 0; i--)
    {
        if (g_Services[i].Teardown != nullptr)
        {
            g_Services[i].Teardown();
        }
    }

    //
    // 9. 释放核心资源（每 CPU 数据 / NPT / 共享数据）。
    //
    NpHvTeardown();

    NpHvLogPrint("NptHook unloaded.\n");
    NpDebugPrint("NptHook unloaded.\n");
}

//
// ============================ 入口 ============================
//

EXTERN_C
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // 注册 R3 管理通道分发器（必须在 IoCreateDevice 之前）。
    //
    NpDevRegisterDispatchers(DriverObject);

    NpDebugPrint("NptHook loading...\n");

    //
    // 支持性检测（AMD + SVM + NPT + SVMDIS 未锁定）。
    //
    if (NpHvIsSvmSupported() == FALSE)
    {
        NpDebugPrint("SVM/NPT is not supported or SVM is locked by BIOS.\n");
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    //
    // 服务 Init（虚拟化前阶段，按序）。
    //
    for (ULONG i = 0; i < NP_SERVICE_COUNT; i++)
    {
        if (g_Services[i].PostVirtualize || g_Services[i].Init == nullptr)
        {
            continue;
        }
        if (g_Services[i].Name == nullptr)  // hookmgr 无独立 Init，走下方专用调用
        {
            continue;
        }
        status = g_Services[i].Init();
        if (!NT_SUCCESS(status))
        {
            NpDebugPrint("Service '%s' init failed: 0x%08x\n",
                         g_Services[i].Name, status);
            //
            // 回滚已初始化的服务后再返回（失败的 i 自身由其 Init 内部
            // 自清理）。裸 return 会把仍在运行的 log 落盘系统线程留在
            // 已卸载的镜像上执行，触发 0xCE
            // （DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS）。
            //
            for (LONG j = static_cast<LONG>(i) - 1; j >= 0; j--)
            {
                if (g_Services[j].Teardown != nullptr)
                {
                    g_Services[j].Teardown();
                }
            }
            return status;
        }
    }

    //
    // Hook 管理器初始化（独立调用，保持旧语义）。
    //
    NpHookManagerInitialize();

    //
    // 核心初始化（每 CPU 数据数组）。
    //
    status = NpHvInitialize();
    if (!NT_SUCCESS(status))
    {
        //
        // 同样必须回滚：log 落盘线程仍在运行，裸 return 触发 0xCE。
        // 此时仅虚拟化前服务已初始化（log / hookmgr / devioctl），按逆序
        // Teardown；PostVirtualize 服务尚未 Init，不能碰。
        //
        for (LONG j = static_cast<LONG>(NP_SERVICE_COUNT) - 1; j >= 0; j--)
        {
            if (!g_Services[j].PostVirtualize &&
                g_Services[j].Teardown != nullptr)
            {
                g_Services[j].Teardown();
            }
        }
        return status;
    }

    //
    // 注册电源回调（睡眠/唤醒时虚拟化状态失效，需要重建）。
    //
    status = NpHvRegisterPowerCallback();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // 虚拟化全部处理器。
    //
    status = NpHvVirtualizeAllProcessors();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    NpDebugPrint("All processors virtualized (%lu).\n", NpHvGetProcessorCount());

    //
    // 启动影子页复位线程（周期性 vmmcall 复位，缩短影子页暴露窗口）。
    //
    status = NpHvStartShadowResetThread();
    if (!NT_SUCCESS(status))
    {
        NpDebugPrint("Failed to start reset thread: 0x%08x\n", status);
        goto Exit;
    }

    //
    // 虚拟化后阶段的服务 Init（业务 Hook）。
    //
    NpDebugPrint("[load] post-virtualize services begin\n");
    for (ULONG i = 0; i < NP_SERVICE_COUNT; i++)
    {
        if (!g_Services[i].PostVirtualize || g_Services[i].Init == nullptr)
        {
            continue;
        }
        NpDebugPrint("[load] post-virt service '%s' start\n",
                     g_Services[i].Name);
        status = g_Services[i].Init();
        if (!NT_SUCCESS(status))
        {
            NpDebugPrint("Service '%s' init failed: 0x%08x\n",
                         g_Services[i].Name, status);
        }
        NpDebugPrint("[load] post-virt service '%s' done\n",
                     g_Services[i].Name);
    }

    DriverObject->DriverUnload = NptDriverUnload;
    NpDebugPrint("[load] all services done, driver loaded\n");
    NpHvLogPrint("NptHook loaded successfully.\n");

    //
    // 自隐藏：从内核模块列表摘除自身（NPTHOOK_SELF_HIDE 开关，
    // 见 NpConfig.h）。必须在一切初始化成功后执行。
    //
    NpSelfHideInitialize(DriverObject);
    return STATUS_SUCCESS;

Exit:
    //
    // 失败回滚：逆序 Teardown。
    //
    if (NpHvIsRunning())
    {
        NpHvDevirtualizeAllProcessors();
    }
    NpHvUnregisterPowerCallback();
    NpHvTeardown();
    for (LONG i = static_cast<LONG>(NP_SERVICE_COUNT) - 1; i >= 0; i--)
    {
        if (g_Services[i].Teardown != nullptr)
        {
            g_Services[i].Teardown();
        }
    }
    return status;
}

