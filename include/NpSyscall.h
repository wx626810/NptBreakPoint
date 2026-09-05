/*!
    @file       NpSyscall.h
    @brief      P0：syscall号/SSDT抽取独立模块（报告§4 P0）
*/
#pragma once
#include <ntifs.h>
#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS NpSyscallInitialize(void);
void NpSyscallTeardown(void);
// 重新从当前进程 PEB 解析 ntdll syscall 号（IOCTL 上下文 = 用户进程）。
// 驱动加载期位于 System 进程（无 ntdll），必须由用户态工具触发刷新。
NTSTATUS NpSyscallRefreshIntercepts(void);
// 动态拦截：prochide 等按需把 syscall 加入/移出跳板表。
NTSTATUS NpSyscallSetIntercept(_In_ const char *NtName, _In_ BOOLEAN Enable);
// 拷贝当前拦截表（跳板固定槽位用；Out 容量不足返回 BUFFER_OVERFLOW）。
NTSTATUS NpSyscallCopyIntercepts(_Out_writes_(Cap) PULONG Out, _In_ ULONG Cap,
                                 _Out_ PULONG OutCount);
ULONG NpSyscallExtractNumber(_In_ const char *NtName);
PVOID NpSyscallResolveAddress(_In_ const char *NtName);
ULONG_PTR NpSyscallFindServiceTable(_Out_ PULONG_PTR OutModuleBase, _Out_ BOOLEAN *OutIs4B);
PVOID NpSyscallGetRoutineByNumber(_In_ ULONG Syscall, _In_ ULONG_PTR TableBase, _In_ ULONG_PTR ModuleBase, _In_ BOOLEAN Is4B);
PVOID NpSyscallResolveRoutine(_In_ const char *NtName, _Out_opt_ ULONG *OutSyscall);
// 已知 syscall 号时的解析入口（驱动加载期可脱离 ntdll 使用）。
PVOID NpSyscallResolveRoutineEx(_In_ const char *NtName, _In_ ULONG KnownSyscall,
                                _Out_opt_ ULONG *OutSyscall);
// 附着任意带 PEB 的用户进程执行回调（驱动加载期解析 syscall 用）。
BOOLEAN NpSyscallRunInUserContext(_In_ void (*Callback)(void *Context),
                                  _Inout_opt_ void *Context);

// P0 预检覆盖：QIP / QSI / RLFE + WVM / RVM / DAP / SCT（RLFE 非 syscall）
#define NPSYSCALL_PRECHECK_COUNT 7
typedef struct _NPSYSCALL_PRECHECK_ENTRY {
    const char *Name;
    PVOID Address;
    ULONG Syscall;
    BOOLEAN IsSyscall;
    BOOLEAN Resolved;
} NPSYSCALL_PRECHECK_ENTRY;
typedef struct _NPSYSCALL_PRECHECK_RESULT {
    ULONG Count;
    NPSYSCALL_PRECHECK_ENTRY Entries[NPSYSCALL_PRECHECK_COUNT];
    ULONG_PTR ServiceTable;
    ULONG_PTR ModuleBase;
    BOOLEAN Is4B;
    BOOLEAN AllPassed;
    BOOLEAN TableCrossChecked;
} NPSYSCALL_PRECHECK_RESULT;
NTSTATUS NpSyscallPrecheck(_Out_ NPSYSCALL_PRECHECK_RESULT *Out);

// LSTAR 拦截表查询：指定 syscall 号是否应拦截（初始化后可用）。
BOOLEAN NpSyscallIsIntercepted(_In_ ULONG SyscallNumber);
#ifdef __cplusplus
}
#endif
