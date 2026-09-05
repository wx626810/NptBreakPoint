#pragma once
#include "NpTypes.h"
extern "C" {
NTSTATUS NpProcessHideInitialize(VOID);
VOID NpProcessHideTeardown(VOID);
NTSTATUS NpProcessHideSetEnabled(BOOLEAN Enable);
BOOLEAN NpProcessHideIsEnabled(VOID);
// LSTAR 分流（P3+）：prochide 走 QSI 动态拦截时由 NpLstarSyscallDispatch 调用。
// 返回 TRUE = 已处理（OutStatus 为 NTSTATUS）；FALSE = 应转发原函数。
BOOLEAN NpProcessHideHandleQsiSplit(_In_ ULONG_PTR InfoClass,
                                    _In_ ULONG_PTR Buffer,
                                    _In_ ULONG_PTR Length,
                                    _In_ ULONG_PTR ReturnLength,
                                    _Out_ PULONG_PTR OutStatus);
NTSTATUS NpProcessHideAdd(const wchar_t* Name);
NTSTATUS NpProcessHideRemove(const wchar_t* Name);
// 按 PID 隐藏（伪附加时自动登记实际调试器，兼容改名场景）。
NTSTATUS NpProcessHideAddPid(ULONG ProcessId);
NTSTATUS NpProcessHideRemovePid(ULONG ProcessId);
VOID NpProcessHideClearAll(VOID);
ULONG NpProcessHideGetCount(VOID);
BOOLEAN NpProcessHideIsStealthActive(VOID);     // 过滤 hook 是否启用（复位线程调速用）

// 枚举已注册的隐藏名到固定宽度宽字符数组（IOCTL_NPHV_PROCESS_HIDE_LIST 用）。
// 持锁拷贝，返回实际条数；Names 为 [MaxEntries][64] 布局，单名截断到 63 字符。
ULONG NpProcessHideCopyNames(_Out_writes_(MaxEntries * 64) wchar_t* Names,
                             ULONG MaxEntries);

// ---- 查看者豁免名单 ----------------------------------------------------
// 名单内的进程调用 NtQuerySystemInformation 时不过滤（自家调试器需要
// 看到并附加目标）。按 EPROCESS.ImageFileName 整名匹配。
NTSTATUS NpProcessWatchAdd(const wchar_t* Name);
NTSTATUS NpProcessWatchRemove(const wchar_t* Name);
ULONG NpProcessWatchCopyNames(_Out_writes_(MaxEntries * 64) wchar_t* Names,
                              ULONG MaxEntries);
} // extern C
