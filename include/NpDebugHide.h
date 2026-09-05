/*!
    @file       NpDebugHide.h

    @brief      services/NpDebugHide 对外接口：X64DBG 调试链路隐藏。

    @details    目标：让 X64DBG 以**原生操作方式**（F2 下断点、读内存、
                附加进程）工作，同时隐藏整条调试链路不被反作弊发现：

                1. NtQueryInformationProcess 伪造
                   - ProcessDebugPort(7)        → 0
                   - ProcessDebugObjectHandle   → STATUS_PORT_NOT_SET
                   - ProcessDebugFlags(0x1F)    → 1（可调试，未附加）
                2. NtWriteVirtualMemory 断点拦截
                   - 调试器写 0xCC（软件断点）→ 不落内存，自动转为
                     NPT 无痕断点（NPHV_BP_FLAG_DEBUGGER 透传模式），
                     内存保持原始字节（反作弊扫不到 CC）
                3. NtReadVirtualMemory 无痕读
                   - 调试器读目标内存 → NPT 物理直读（NpMemAccess），
                     返回真实内容

                受保护进程集（IOCTL 注册）：只对注册的目标进程生效，
                普通进程的 IO 零影响。Hook 用现有 NpHook 无痕框架
                （不修改任何 Guest 字节）。
 */
#pragma once

#include "NpTypes.h"

extern "C" {

// 服务初始化（虚拟化后调用）：受保护进程集初始化。
NTSTATUS NpDebugHideInitialize(
    VOID);

// 服务清理（去虚拟化后调用）：卸载全部 Hook、清空进程集。
VOID NpDebugHideTeardown(
    VOID);

// 开启/关闭调试链路隐藏（安装/卸载 Nt* Hook）。
NTSTATUS NpDebugHideSetEnabled(
    _In_ BOOLEAN Enable);

// 是否已开启。
BOOLEAN NpDebugHideIsEnabled(
    VOID);

// 注册/注销受保护进程（调试目标）。模式决定语义：
//   白名单：集合 = 隐藏目标；黑名单：集合 = 排除目标（不隐藏）。
NTSTATUS NpDebugHideProtectProcess(
    _In_ ULONG ProcessId,
    _In_ BOOLEAN Protect);

// 切换隐藏模式（NPHV_DEBUG_MODE_WHITELIST / NPHV_DEBUG_MODE_BLACKLIST）。
NTSTATUS NpDebugHideSetMode(
    _In_ ULONG Mode);

// 查询当前隐藏模式。
ULONG NpDebugHideGetMode(
    VOID);

// 查询指定 PID 是否"应隐藏"（已按模式取反）。
BOOLEAN NpDebugHideIsProtected(
    _In_ ULONG ProcessId);

// 受保护进程数量（R3 状态查询用）。
ULONG NpDebugHideGetProtectedCount(
    VOID);

// 进程退出联动清理：受害 PID 退出时移出保护集（防 PID 复用误保护）。
// 由 PatchView 的进程通知回调调用（PASSIVE_LEVEL）。
VOID NpDebugHideOnProcessExit(
    _In_ ULONG Pid);

// 登记调试器 PID 锚点（附加瞬间/识别扫描后调用）。
VOID NpDebugHideNoteDebugger(
    _In_ ULONG VictimPid,
    _In_ ULONG DebuggerPid);

// 查询某进程的已登记调试器是否为给定 PID。
// 真实附加（passthrough）模式下 pseudo 会话不存在，NpPseudoDbgFindByDebugger
// 恒返回 FALSE —— overlay 呈现 0xCC 与 continue 的 target 解析必须用本函数。
NTSTATUS NpDebugHideQueueEnable(
    _In_ BOOLEAN Enable);
BOOLEAN NpDebugHideIsWorkPending(
    VOID);

BOOLEAN NpDebugHideIsDebuggerOf(
    _In_ ULONG DebuggerPid,
    _In_ ULONG VictimPid);

//
// ============================ LSTAR 分流包装（P3） ============================
//
// 供 NpLstarSyscallDispatch 复用现有回调语义：
// 返回 TRUE = 已处理（OutStatus 为 NTSTATUS）；FALSE = 应转发原函数。
//
BOOLEAN NpDebugHideQueryProcessInfoSplit(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG InfoClass,
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR OutStatus);

BOOLEAN NpDebugHideReadVirtualMemorySplit(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN DebuggerView,
    _Out_ PSIZE_T BytesRead,
    _Out_ PNTSTATUS OutStatus);

BOOLEAN NpDebugHideWriteVirtualMemorySplit(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN DebuggerView,
    _Out_ PSIZE_T BytesWritten,
    _Out_ PNTSTATUS OutStatus);

} // extern "C"
