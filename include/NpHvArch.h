/*!
    @file       NpHvArch.h

    @brief      core 层内部接口：通用生命周期层（NpHv.cpp）与
                架构专属实现（NpHvArchSvm.cpp）之间的契约。

    @details    架构隔离设计：
                - NpHv.cpp      通用：生命周期编排、事件、数据访问、复位线程
                - NpHvArchSvm.cpp AMD 专属：SVM 检测、VMCB/NPT、单核虚拟化
                - 未来 Intel 支持：新增 NpHvArchVmx.cpp，实现同一组接口
                （NpArchVmxVirtualizeProcessor / NpArchVmxBuildNestedPageTables 等），
                NpHv.cpp 与 VMEXIT 分发引擎原样复用。
 */
#pragma once

#include "NpTypes.h"
#include "NpHv.h"

extern "C" {

//
// ============================ 内部状态访问 ============================
//
// 仅供 arch 层实现使用（NpHv.cpp 的私有状态）。
//

PVIRTUAL_PROCESSOR_DATA* NpHvGetVpDataArrayInternal(
    VOID);

PSHARED_VIRTUAL_PROCESSOR_DATA NpHvGetSharedVpDataInternal(
    VOID);

// 触发生命周期事件（arch 层在单核虚拟化/去虚拟化时调用）。
VOID NpHvFireEventInternal(
    _In_ NP_HV_EVENT Event);

//
// ============================ arch 层导出接口 ============================
//
// 每个架构实现（SVM/VMX）必须提供以下能力。
//

// 构建 MSR 权限位图（反检测拦截位）。
VOID NpArchSvmBuildMsrPermissionsMap(
    _Inout_ PVOID MsrPermissionsMap);

// 构建 512GB 恒等映射页表（GPA == HPA）。
VOID NpArchSvmBuildNestedPageTables(
    _Out_ PNPT_ROOT Root);

// 虚拟化单个处理器（进入 VM 循环，SvLaunchVm 不返回）。
NTSTATUS NpArchSvmVirtualizeProcessor(
    _In_ ULONG CpuIndex,
    _In_opt_ PVOID Context);

// 请求单个处理器去虚拟化（CPUID 卸载后门）。
NTSTATUS NpArchSvmDevirtualizeProcessor(
    _In_ ULONG CpuIndex,
    _In_opt_ PVOID Context);

// 检测本处理器是否已被本框架虚拟化（CPUID 后门探测）。
BOOLEAN NpArchIsHypervisorInstalled(
    VOID);

} // extern "C"
