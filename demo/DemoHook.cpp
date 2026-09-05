/*!
    @file       DemoHook.cpp

    @brief      demo 业务层：演示 Hook（NtQuerySystemInformation）。

    @details    这是"业务层"的样板——新功能模块的接入方式：
                - 导出 Install/Teardown 两个函数
                - 在 NptHook.cpp 的服务注册表中登记
                - Install 在虚拟化完成后被调用
                复制本文件即可创建你自己的功能模块。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"

static PHOOK_INFO g_DemoHook = nullptr;
static volatile LONG64 g_DemoHookCount = 0;

/*!
    @brief      NtQuerySystemInformation 的演示回调。

    @details    统计触发次数并抽样记录日志，随后放行（不拦截）。
                注意：回调在 Guest 上下文执行，必须遵守 IRQL 约束；
                且回调内禁止再次调用被 Hook 的函数（会递归触发）。
 */
_Use_decl_annotations_
BOOLEAN
NtQuerySystemInformationHookCallback(
    PHOOK_CALL_CONTEXT Context)
{
    LONG64 count = InterlockedIncrement64(&g_DemoHookCount);
    ULONG infoClass = static_cast<ULONG>(Context->Rcx & MAXUINT32);

    //
    // 抽样记录（每 200 次记一行，避免日志洪泛）。
    //
    if ((count % 200) == 1)
    {
        NpHvLogPrint("[demo] NtQuerySystemInformation: class=%lu count=%lld ret=%p\n",
                     infoClass,
                     count,
                     reinterpret_cast<PVOID>(Context->ReturnAddress));
    }

    //
    // 放行：执行原始函数。
    //
    return FALSE;
}

_Use_decl_annotations_
extern "C"
NTSTATUS
NpDemoHooksInstall(
    VOID)
{
    UNICODE_STRING routineName;
    PVOID address;

    RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
    address = MmGetSystemRoutineAddress(&routineName);
    if (address == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    return NpHookInstallHook(reinterpret_cast<ULONG_PTR>(address),
                             NtQuerySystemInformationHookCallback,
                             &g_DemoHook);
}

_Use_decl_annotations_
extern "C"
VOID
NpDemoHooksTeardown(
    VOID)
{
    //
    // 卸载阶段由 NpHookUninstallAllHooks 统一摘除（延迟释放），
    // 这里无需单独处理。
    //
}
