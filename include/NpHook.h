/*!
    @file       NpHook.h

    @brief      services/NpHook 模块对外接口：NPT Hook（方案C 克隆引擎）
                的安装/卸载/运行时接口，及 PatchView 用户态隐匿补丁。
 */
#pragma once

#include "NpTypes.h"
#include "NpHv.h"       // PGUEST_CONTEXT（VMEXIT handler 注册表签名需要）
#include "NpIoctl.h"    // NPHV_PATCH_LIST_RESPONSE（补丁列表接口）

extern "C" {

// 安装 NPT Hook（不修改 Guest 字节；返回句柄）。
NTSTATUS NpHookInstallHook(
    _In_ ULONG_PTR OriginalAddress,
    _In_ HOOK_CALLBACK Callback,
    _Out_ PHOOK_INFO* HookInfo);

// FreeResources=FALSE 时延迟释放（挂退休链表），配合 NpHookFreeRetiredHooks。
// 驱动卸载路径必须传 FALSE，避免跳板/影子页 use-after-free。
NTSTATUS NpHookUninstallHook(
    _In_ PHOOK_INFO HookInfo,
    _In_ BOOLEAN FreeResources);

NTSTATUS NpHookUninstallAllHooks(
    _In_ BOOLEAN FreeResources);

// 释放退休链表中的全部 Hook 资源（虚拟化关闭后调用）。
NTSTATUS NpHookFreeRetiredHooks(
    VOID);

// Hook 管理器初始化（DriverEntry 组装时调用）。
VOID NpHookManagerInitialize(
    VOID);

// 统计当前活动 Hook 数量（R3 状态查询用）。
ULONG NpHookGetActiveCount(
    VOID);

// 供 VMEXIT 处理（core 层）调用的 Hook 运行时接口。
BOOLEAN NpHookHandleNpf(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR FaultGpa,
    _In_ ULONG_PTR FaultRip,
    _In_ ULONG ErrorCode);

BOOLEAN NpHookHandleBreakpoint(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData);

// 方案C：被_hook 页的数据读/写违例处理（恒等+TF 单步一条指令收口）。
BOOLEAN NpHookHandleDataFault(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR FaultGpa,
    _In_ ULONG FaultErrorCode);

// 方案C：数据单步的 #DB 收口（恢复武装态；写则同步全部副本）。
BOOLEAN NpHookHandleDebugStep(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData);

BOOLEAN NpHookResetAllShadows(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData);

// 把指定 GPA 的 NPT 叶子恢复为恒等映射（自愈/卸载用）。
VOID NpHookRestoreIdentity(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR Gpa);

// 尝试把已恢复恒等的 4KB 拆分页合并回 2MB 大页并释放 PT 池页
// （防 PT 页池耗尽；VMEXIT 高 IRQL 路径安全）。
VOID NpHookTryMergeLargePage(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR Gpa);

//
// ============================ NPT 叶子操作（导出给同层服务复用） ============================
//

// 原子更新指定 GPA 的叶子映射（Hpa + 权限），并标记下次 VMRUN 刷新 TLB。
VOID NpHookSetLeaf(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR Gpa,
    _In_ ULONG_PTR Hpa,
    _In_ BOOLEAN NoExecute,
    _In_ BOOLEAN Writable);

// 获取指定 GPA 的 NPT 叶子项指针（必要时拆分 2MB 大页；VMEXIT 安全）。
BOOLEAN NpHookGetLeafEntry(
    _In_ PNPT_ROOT Root,
    _In_ ULONG_PTR Gpa,
    _Out_ PNPT_ENTRY* OutLeaf);

// 查询指定页（GPA，页对齐）是否已被 Hook 占用（同页只允许一种占用者）。
BOOLEAN NpHookIsPageHooked(
    _In_ ULONG_PTR PageGpa);

// 电源恢复后重新应用所有 Hook（NPT 在睡眠期间被清空）。
NTSTATUS NpHookReapplyAllHooks(
    VOID);

//
// ============================ PatchView（用户态隐匿补丁） ============================
//

// 取指违例：重定向到补丁克隆同偏移（叶子保持 not-present 武装）。
BOOLEAN NpPatchViewHandleNpf(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR FaultGpa,
    _In_ ULONG_PTR FaultRip,
    _In_ ULONG ErrorCode);

// 数据违例：按观察者分流源帧（安装者→克隆视图，其他→真页视图），
// TF 单步一条指令后由 NpPatchViewHandleDebugStep 收口。
BOOLEAN NpPatchViewHandleDataFault(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG_PTR FaultGpa,
    _In_ ULONG FaultErrorCode);

// #DB 收口。
BOOLEAN NpPatchViewHandleDebugStep(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData);

// 应用一次补丁写入（WVM 自动转换 / IOCTL 安装共用）。目标页视图不存在时
// 自动创建（需 PASSIVE_LEVEL）。返回 FALSE = 无法承接（调用方回落原写）。
BOOLEAN NpPvApplyWrite(
    _In_ ULONG VictimPid,
    _In_ ULONG WriterPid,
    _In_ ULONG_PTR Va,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length);

// 卸载流程：恢复全部补丁页恒等映射（虚拟化仍开启时调用）+ 转入退休。
VOID NpPatchViewUnloadBegin(
    VOID);

// 驱动卸载末段：释放全部退休 PatchView 资源（虚拟化关闭后调用）。
VOID NpPatchViewFreeRetired(
    VOID);

// 按 VA 移除单个补丁视图（恢复恒等映射，资源转退休延迟释放）。
NTSTATUS NpPatchViewRemove(
    _In_ ULONG VictimPid,
    _In_ ULONG_PTR Va);

// 枚举活动补丁视图（R3 查询用）。
VOID NpPatchViewList(
    _Out_ PNPHV_PATCH_LIST_RESPONSE Resp);

// B3 漂移校验：校验全部活动视图的物理帧一致性，漂移即拆除
// （PASSIVE_LEVEL；复位线程节流调用）。
VOID NpPatchViewValidateAll(
    VOID);

} // extern "C"
