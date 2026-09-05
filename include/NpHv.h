/*!
    @file       NpHv.h

    @brief      core 层对外接口：每 CPU 数据访问、虚拟化生命周期、
                VMEXIT 上下文、生命周期事件。上层（services/demo）
                只允许通过本头文件访问 Hypervisor 核心。
 */
#pragma once

#include "NpTypes.h"
#include "NpConfig.h"

extern "C" {

//
// ============================ 每 CPU 数据访问 ============================
//

// 获取每处理器数据（按全局 CPU 索引）。
NTSTATUS NpHvGetProcessorData(
    _In_ ULONG CpuIndex,
    _Out_ PVIRTUAL_PROCESSOR_DATA* OutVpData);

// 获取处理器数量。
ULONG NpHvGetProcessorCount(
    VOID);

// Hypervisor 是否在运行。
BOOLEAN NpHvIsRunning(
    VOID);

//
// ============================ 虚拟化生命周期 ============================
//

// 检测 AMD SVM + NPT + SVMDIS 未锁定。
BOOLEAN NpHvIsSvmSupported(
    VOID);

// 初始化核心（分配每 CPU 数据数组；DriverEntry 组装时调用）。
NTSTATUS NpHvInitialize(
    VOID);

// 清理核心（释放每 CPU 数据/NPT/共享数据；必须先去虚拟化）。
VOID NpHvTeardown(
    VOID);

// 虚拟化全部处理器。
NTSTATUS NpHvVirtualizeAllProcessors(
    VOID);

// 去虚拟化全部处理器（必须在无 Hook 执行者、排空完成后调用）。
VOID NpHvDevirtualizeAllProcessors(
    VOID);

// 启动影子页复位线程（周期 vmmcall 复位影子页）。
NTSTATUS NpHvStartShadowResetThread(
    VOID);

// 请求停止复位线程并等待退出（卸载路径）。
VOID NpHvStopShadowResetThread(
    VOID);

// 为指定 CPU 构建 NPT（恒等映射）。
NTSTATUS NpHvBuildNpt(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData);

//
// ============================ 电源 ============================
//

// 注册 \Callback\PowerState 电源回调（DriverEntry 组装时调用）。
NTSTATUS NpHvRegisterPowerCallback(
    VOID);

// 注销电源回调（卸载路径）。
VOID NpHvUnregisterPowerCallback(
    VOID);

// 广播电源恢复事件（内部：NpHvPower.cpp 唤醒路径调用）。
VOID NpHvFireEventPowerResume(
    VOID);

//
// ============================ 驱动自隐藏 ============================
//
// 加载后从内核模块列表（PsLoadedModuleList 等）摘除自身。
// 开关：编译期 NPTHOOK_SELF_HIDE（NpConfig.h）+ 运行时变量。
//

// 加载完成后调用（DriverEntry 成功路径，组装层调用）。
VOID NpSelfHideInitialize(
    _In_ PDRIVER_OBJECT DriverObject);

// 卸载路径调用（必须在任何清理之前，链回模块项）。
VOID NpSelfHideRestore(
    VOID);

// 查询自隐藏是否开启（R3 状态查询用）。
BOOLEAN NpSelfHideIsEnabled(
    VOID);

// 运行时切换（预留；当前仅加载期决定，返回 STATUS_NOT_IMPLEMENTED）。
NTSTATUS NpSelfHideSetEnabled(
    _In_ BOOLEAN Enabled);

//
// ============================ VMEXIT 上下文 ============================
//
// GUEST_CONTEXT 由 VMEXIT 分发器在每次退出时构造，传给各 handler。
// VpRegs 指向栈上的 GUEST_REGISTERS（asm PUSHAQ 区域）。
//

typedef struct _GUEST_CONTEXT
{
    PGUEST_REGISTERS VpRegs;        // Guest 通用寄存器（可修改）
    BOOLEAN ExitVm;                 // 置 TRUE 请求卸载 Hypervisor（本 CPU）
} GUEST_CONTEXT, *PGUEST_CONTEXT;

//
// ============================ VMEXIT handler 注册表 ============================
//
// 新功能通过 NpHvRegisterVmExitHandler 挂接 VMEXIT 处理。
// handler 返回 TRUE = 已处理（分发器不再走内置逻辑）；
//           FALSE = 未处理（继续调用内置处理器）。
// 同一 ExitCode 可注册多个，先注册先调用，任一返回 TRUE 即终止。
//

typedef BOOLEAN(*NP_VMEXIT_HANDLER)(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
                                    _Inout_ PGUEST_CONTEXT GuestContext);

NTSTATUS NpHvRegisterVmExitHandler(
    _In_ ULONG ExitCode,
    _In_ NP_VMEXIT_HANDLER Handler);

// 每次 VMEXIT 分发完成后、返回 Guest 前调用（服务侧快速收紧用）。
typedef VOID(*NP_POST_EXIT_CALLBACK)(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData);

NTSTATUS NpHvRegisterPostExitCallback(
    _In_ NP_POST_EXIT_CALLBACK Callback);

//
// ============================ 生命周期事件 ============================
//
// 核心广播以下事件；服务模块通过 NpHvRegisterEvent 订阅。
// 事件回调在 DISPATCH_LEVEL 以下、对应 CPU 的上下文执行。
//

typedef enum _NP_HV_EVENT
{
    NpHvEventVirtualizeBegin = 0,   // 虚拟化开始前（每 CPU）
    NpHvEventVirtualizeEnd,         // 虚拟化完成后（每 CPU）
    NpHvEventDevirtualizeBegin,     // 去虚拟化开始前（每 CPU）
    NpHvEventDevirtualizeEnd,       // 去虚拟化完成后（每 CPU）
    NpHvEventPowerResume,           // 电源唤醒、重新虚拟化后（PASSIVE）
    NpHvEventMax
} NP_HV_EVENT;

typedef VOID(*NP_HV_EVENT_CALLBACK)(_In_ NP_HV_EVENT Event,
                                    _In_opt_ PVOID Context);

// 注册/注销生命周期事件回调（回调表容量有限，注册失败返回错误）。
NTSTATUS NpHvRegisterEvent(
    _In_ NP_HV_EVENT Event,
    _In_ NP_HV_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context);

VOID NpHvUnregisterEvent(
    _In_ NP_HV_EVENT Event,
    _In_ NP_HV_EVENT_CALLBACK Callback);

} // extern "C"
