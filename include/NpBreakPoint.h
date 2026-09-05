/*!
    @file       NpBreakPoint.h

    @brief      services/NpBreakPoint 对外接口：NPT 无痕断点 / NPT 监视
                （模拟硬件断点）/ 无痕内存读写。

    @details    与 NpHook 的区别：
                - NpHook 是"无痕 Hook"：命中后重定向执行流到跳板回调；
                - NpBreakPoint 是"无痕调试器"：命中后记录现场并暂停 /
                  自动单步 / 重新布点，不修改任何 Guest 字节。
                两者共用 NPT 叶子操作（NpHookSetLeaf）与每 CPU PT 页池，
                同一 4KB 页只允许一种占用者（NpHookIsPageHooked 检查）。

    AMD 实现要点（对照 Intel EPT，见 kanxue 帖子）：
    - AMD NPT 无 execute-only 页 → 用"影子页0(干净,NX) ↔ 影子页1(CC)"
      双视图实现无痕 INT3；
    - AMD SVM 无 Intel MTF → 单步用 Guest RFLAGS.TF + 拦截 #DB(向量1)；
    - 拦截 #BP 时 VMCB.Rip 指向 INT3 本身（Intel 需 rip-1），
      断点匹配直接使用 StateSaveArea.Rip。
 */
#pragma once

#include "NpTypes.h"
#include "NpIoctl.h"

extern "C" {

//
// ============================ 生命周期 ============================
//

// 服务初始化（虚拟化完成后调用）：分配每 CPU 状态、注册 VMEXIT handler、
// 注册电源恢复事件。
NTSTATUS NpBreakPointInitialize(
    VOID);

// 服务清理（去虚拟化完成后调用）：释放全部资源（含退休链表）。
VOID NpBreakPointTeardown(
    VOID);

// 驱动卸载路径：摘除全部断点/监视并恢复恒等映射（虚拟化在位时调用）。
// FreeResources=FALSE 时挂入退休链表，由 NpBreakPointFreeRetired 释放。
NTSTATUS NpBreakPointUninstallAll(
    _In_ BOOLEAN FreeResources);

// 按目标 PID 摘除全部用户态断点（调试器分离/进程退出时调用，释放 MDL）。
NTSTATUS NpBreakPointUninstallByPid(
    _In_ ULONG ProcessId);

// 释放退休链表资源（去虚拟化完成后调用）。
NTSTATUS NpBreakPointFreeRetired(
    VOID);

// 电源恢复后重新应用全部断点/监视（NPT 睡眠期间被重建为恒等映射）。
NTSTATUS NpBreakPointReapplyAll(
    VOID);

//
// ============================ 无痕断点 ============================
//

// 安装断点。Flags = NPHV_BP_FLAG_*（0=自动单步模式）。
NTSTATUS NpBreakPointInstall(
    _In_ ULONG_PTR Address,
    _In_ ULONG Flags,
    _Out_ PULONG OutBpId);

// 安装断点（扩展）：Process 非空时支持用户态地址（AttachProcess 读原始页）；
// Process 为空要求内核地址。Process 引用计数由调用方管理（本函数不增减）。
NTSTATUS NpBreakPointInstallEx(
    _In_ ULONG_PTR Address,
    _In_ ULONG Flags,
    _In_opt_ PEPROCESS Process,
    _Out_opt_ PULONG OutBpId);

// 卸载断点。FreeResources=FALSE 时延迟释放（挂退休链表）。
NTSTATUS NpBreakPointUninstall(
    _In_ ULONG BpId,
    _In_ BOOLEAN FreeResources);

// 查询活动断点数量。
ULONG NpBreakPointGetActiveCount(
    VOID);

// 快照断点列表（R3 查询用）。
NTSTATUS NpBreakPointQuery(
    _Out_writes_(MaxCount) PNPHV_BREAKPOINT_INFO_ENTRY Entries,
    _In_ ULONG MaxCount,
    _Out_ PULONG OutCount);

// 继续被暂停（HALT）的断点。BpId=0 表示全部。
// 实现：在断点暂停所在 CPU 上执行 vmmcall（VMMCALL_BP_CONTINUE）——
// 修改 VMCB.Rflags(TF) 必须在目标 CPU 自己的 VMEXIT 上下文进行。
NTSTATUS NpBreakPointContinue(
    _In_ ULONG BpId);

// 重新武装 DEBUGGER 模式断点（调试器恢复断点/重写 0xCC 时调用）。
// 清除 DebuggerPaused 并在全部 CPU 恢复影子页0 NX=1；仅处理
// DEBUGGER 模式且处于暂停中的断点，其余直接忽略。PASSIVE 上下文。
VOID NpBreakPointReArmByAddress(
    _In_ ULONG_PTR Address);

// 查询指定页是否已被断点占用（同页互斥检查）。
BOOLEAN NpBreakPointIsPageOccupied(
    _In_ ULONG_PTR PageGpa);

// 判断指定 GPA 页当前是否被 HALT 钉住（看门狗豁免用；任意 IRQL 可调）。
BOOLEAN NpBreakPointIsHaltedPage(
    _In_ ULONG_PTR PageGpa);

//
// ============================ NPT 监视（模拟硬件断点） ============================
//

// 安装数据访问监视（按页，AccessType = NPHV_MON_ACCESS_*）。
NTSTATUS NpBreakPointInstallMonitor(
    _In_ ULONG_PTR Address,
    _In_ ULONG AccessType,
    _Out_ PULONG OutMonitorId);

// 卸载监视。
NTSTATUS NpBreakPointUninstallMonitor(
    _In_ ULONG MonitorId,
    _In_ BOOLEAN FreeResources);

// 安装 PEB 影子监视（NPT）：把目标进程 PEB 页经 NPT 重定向到干净副本，
// BeingDebugged/NtGlobalFlag 由影子页呈现，不再周期写真实 PEB。
NTSTATUS NpBreakPointInstallPebShadow(
    _In_ PEPROCESS Process,
    _Out_ PULONG OutMonitorId);

// 摘除指定进程的 PEB 影子监视（hide 关闭/解保护时调用）。
NTSTATUS NpBreakPointUninstallPebShadowByPid(
    _In_ ULONG ProcessId);

// 物理直读路径：命中 PEB 影子监视时返回影子页物理地址（读干净副本）。
BOOLEAN NpBreakPointGetPebShadowPa(
    _In_ ULONG_PTR PageGpa,
    _Out_ PULONG_PTR OutShadowPa);

// 目标进程是否已有 PEB 影子监视（清扫线程据此跳过真实页写入）。
BOOLEAN NpBreakPointHasPebShadow(
    _In_ PEPROCESS Process);

// 调试器把断点地址写回原字节（删除/禁用断点）时调用：摘除 DEBUGGER 断点。
// continue 的恢复步也会写回原字节，但之后调试器会重写 0xCC 重新安装断点，
// 所以这里一律先卸载，由后续 0xCC 写重新武装。
BOOLEAN NpBreakPointTryDeleteDebuggerBp(
    _In_ ULONG_PTR Address,
    _In_ UCHAR OriginalByte,
    _In_ BOOLEAN ExternalWriter,
    _In_ ULONG Length);

// 调试器 continue 时清扫"僵尸断点"：x64dbg 删除断点可能完全不写内存
// （只有内部 enabled 为真才调 DeleteBPX），导致驱动侧收不到任何信号、
// 断点永久残留。判据是"处于 DebuggerPaused 但本轮没有 step-over 准备
// 动作" —— 调试器若仍认这个断点，恢复前必然先写回原字节再单步。
// 详见 NpBreakPoint.cpp 中该函数注释。
VOID NpBreakPointReapZombieOnContinue(
    _In_ ULONG TargetPid);

// 调试器在断点地址写入补丁（非原字节/多字节）时：把补丁落真实页、刷新
// 影子页并保持断点武装，使补丁对执行生效且断点状态不变。
NTSTATUS NpBreakPointRefreshShadowOnPatch(
    _In_ ULONG_PTR Address,
    _In_ PEPROCESS Process,
    _In_ PVOID UserBuffer,
    _In_ ULONG Length);

// 地址是否命中活动 DEBUGGER 断点（WVM 恢复写/删除写时避免建补丁视图）。
BOOLEAN NpBreakPointIsDebuggerBpAt(
    _In_ ULONG_PTR Address);

//
// ============================ DR 硬件断点虚拟化（drprobe） ============================
//
// SVM 拦截 Guest 对 DR0-3/DR6/DR7 的读写：
// - 写拦截：记录假 DR（探测调试器设置的硬件断点）；
// - 读拦截：回显假 DR（伪装断点已生效）。
// 开启后调试器硬件断点可被 R3 侧读取并转发为 NPT 断点/监视。
//

// 开启/关闭 DR 探测（逐 CPU vmmcall 修改各自 VMCB 拦截位）。
NTSTATUS NpBreakPointSetDrProbe(
    _In_ BOOLEAN Enable);

// 查询假 DR 状态（CPU 0 快照：假 DR 值 + 最近使能槽的断点地址）。
NTSTATUS NpBreakPointQueryDrState(
    _Out_ PNPHV_DRSTATE_RESPONSE Response);

// DR 访问 VMEXIT 处理器（注册表用；exit code 见 NpSvm.h VMEXIT_DR*）。
BOOLEAN NpBreakPointHandleDrAccess(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_ ULONG ExitCode);

//
// ============================ VMEXIT 处理器（注册表用） ============================
//
// 以下函数由 NpBreakPointInitialize 注册到 NpHvRegisterVmExitHandler；
// 返回 TRUE=已处理（分发器不再走内置逻辑），FALSE=回落。
//

// #NPF（嵌套页错误）：取指违例→断点状态机；数据违例→监视。
BOOLEAN NpBreakPointHandleNpf(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

// #BP（INT3）：命中→记录现场→暂停或单步。
BOOLEAN NpBreakPointHandleBreakpoint(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

// #DB（调试异常）：本框架单步完成→重新武装/解除；否则回落给 Guest。
BOOLEAN NpBreakPointHandleDebug(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

// VMMCALL：RESET_SHADOWS（复位断点/监视影子页）+ BP_CONTINUE（继续断点）。
// 返回 FALSE 让内置 VMMCALL 处理器继续（更新 NRip / Hook 影子复位）。
BOOLEAN NpBreakPointHandleVmmcall(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

BOOLEAN NpBreakPointOverlayCcForRead(
    _In_ ULONG TargetPid,
    _In_ ULONG_PTR StartVa,
    _In_ ULONG Length,
    _Inout_ PUCHAR Buffer
    );

// 非暂停期收到 0xCC 写且断点已存在：不是 step-over 的重新武装，而是删除
// （x64dbg 的 oldbytes 可能被污染成 0xCC）。详见 cpp 中注释。
BOOLEAN NpBreakPointDeleteByCcWrite(
    _In_ ULONG_PTR Address);
} // extern "C"
