#pragma once
#include "NpConfig.h"
#include "NptHook.hpp"
#ifdef __cplusplus
extern "C" {
#endif
#define NPHV_PSEUDO_MAX_SESSIONS    16
#define NPHV_PSEUDO_MAX_EVENTS      256
#define NPHV_PSEUDO_MAX_MODULES     128

// 实测目标 x64dbg 会把伪 LOAD_DLL 事件误读成异常，先跳过，
// 由 x64dbg 自行枚举模块。1 = 不发送 LOAD_DLL。
#define NP_PSEUDO_SKIP_LOAD_DLL     1

// 异常联合体相对标准 0x10 的额外偏移。标准 Windows DEBUG_EVENT = 0x10，
// 应保持 0x00；仅当调试特定构建的“未识别断点”路径（cbException）时，
// 可临时改成 0x08 并启用下方 ReservedPad。x64dbg 自设断点（F2）走
// TitanEngine BPX 表识别路径，标准 0x10 即可。
#define NP_PSEUDO_EXCEPTION_UNION_SHIFT 0x00

// DEBUG_EVENT 镜像（x64 布局与 winbase.h 一致；内核头不引入用户态结构）。
// 注意：EXCEPTION_DEBUG_INFO = EXCEPTION_RECORD + dwFirstChance，不含句柄；
// 事件内 hProcess/hThread 只出现在 CREATE_* 事件里。
typedef struct _NPHV_DEBUG_EVENT {
    ULONG  dwDebugEventCode;
    ULONG  dwProcessId;
    ULONG  dwThreadId;
    ULONG  Reserved0;
    union {
        struct {
#if NP_PSEUDO_EXCEPTION_UNION_SHIFT >= 8
            ULONG_PTR ReservedPad;  // 实测目标把异常联合体当 0x18 起解析
#endif
            ULONG ExceptionCode;
            ULONG ExceptionFlags;
            ULONG_PTR ExceptionRecord;
            ULONG_PTR ExceptionAddress;
            ULONG NumberParameters;
            ULONG Reserved1;
            ULONG_PTR ExceptionInformation[15];
            ULONG dwFirstChance;
            ULONG Reserved2;
        } Exception;
        struct {
            ULONG_PTR hThread;
            ULONG_PTR lpThreadLocalBase;
            ULONG_PTR lpStartAddress;
        } CreateThread;
        struct {
            ULONG_PTR hFile;
            ULONG_PTR hProcess;
            ULONG_PTR hThread;
            ULONG_PTR lpBaseOfImage;
            ULONG dwDebugInfoFileOffset;
            ULONG nDebugInfoSize;
            ULONG_PTR lpThreadLocalBase;
            ULONG_PTR lpStartAddress;
            ULONG_PTR lpImageName;
            USHORT fUnicode;
            USHORT Reserved2;
            ULONG Reserved3;
        } CreateProcessInfo;
        struct {
            ULONG_PTR hFile;
            ULONG_PTR lpBaseOfDll;
            ULONG dwDebugInfoFileOffset;
            ULONG nDebugInfoSize;
            ULONG_PTR lpImageName;
            USHORT fUnicode;
            USHORT Reserved4;
            ULONG Reserved5;
        } LoadDll;
    } u;
} NPHV_DEBUG_EVENT, *PNPHV_DEBUG_EVENT;

// 调试事件代码（winbase.h）
#define NPHV_DEBUG_EVENT_EXCEPTION          1
#define NPHV_DEBUG_EVENT_CREATE_THREAD      2
#define NPHV_DEBUG_EVENT_CREATE_PROCESS     3
#define NPHV_DEBUG_EVENT_EXIT_THREAD        4
#define NPHV_DEBUG_EVENT_EXIT_PROCESS       5
#define NPHV_DEBUG_EVENT_LOAD_DLL           6
#define NPHV_DEBUG_EVENT_UNLOAD_DLL         7
#define NPHV_DEBUG_EVENT_OUTPUT_DEBUG_STRING 8

// 异常代码
#define NPHV_EXCEPTION_BREAKPOINT           0x80000003
#define NPHV_EXCEPTION_SINGLE_STEP          0x80000004

NTSTATUS NpPseudoDbgInitialize(void);
void NpPseudoDbgTeardown(void);

// P2 伪附加状态机（LSTAR 分发器调用；PASSIVE_LEVEL）。
NTSTATUS NpPseudoDbgCreateSession(ULONG TargetPid, ULONG DebuggerPid, ULONG *OutSessionId);
NTSTATUS NpPseudoDbgRemoveSession(ULONG SessionId);
NTSTATUS NpPseudoDbgDetachByTarget(ULONG TargetPid, ULONG DebuggerPid);
BOOLEAN  NpPseudoDbgIsSessionTarget(ULONG TargetPid, ULONG DebuggerPid);
BOOLEAN  NpPseudoDbgIsTargetAttached(ULONG TargetPid);
ULONG    NpPseudoDbgGetSessionCount(void);
// Wait/Continue 的句柄是调试对象句柄（非进程句柄），按调试器 PID 回退定位。
BOOLEAN  NpPseudoDbgFindByDebugger(ULONG DebuggerPid,
                                   _Out_opt_ PULONG OutTargetPid,
                                   _Out_opt_ PULONG OutSessionId);

// Wait 语义：阻塞调试器线程直到事件就绪/超时，然后构造 DEBUG_EVENT
// （含调试器进程上下文真实句柄）写入用户缓冲。
NTSTATUS NpPseudoDbgWaitEvent(ULONG TargetPid, ULONG DebuggerPid,
                              BOOLEAN Alertable, PLARGE_INTEGER Timeout,
                              PVOID UserEventOut, ULONG EventSize);

// Continue：确认事件并恢复冻结线程/重武装断点。
NTSTATUS NpPseudoDbgContinue(ULONG TargetPid, ULONG DebuggerPid,
                             ULONG ContinueStatus);
NTSTATUS NpPseudoDbgWaitEventById(ULONG SessionId, PVOID UserEventOut,
                                  ULONG EventSize);
NTSTATUS NpPseudoDbgWaitReadyById(ULONG SessionId);
NTSTATUS NpPseudoDbgContinueById(ULONG SessionId, ULONG ContinueStatus);
BOOLEAN NpPseudoDbgGetSessionInfo(ULONG SessionId, PULONG TargetPid,
                                  PULONG DebuggerPid, PULONG EventCount);

// 附加瞬间快照：CREATE_PROCESS + CREATE_THREAD + LOAD_DLL（PEB.Ldr 枚举）。
NTSTATUS NpPseudoDbgSnapshot(ULONG TargetPid, ULONG DebuggerPid);

// 运行期事件入队：断点命中（NpBreakPoint 调用，可处于 VMEXIT 高 IRQL）。
VOID NpPseudoDbgQueueBpEvent(ULONG TargetPid, ULONG_PTR BpVa, ULONG Tid,
                             ULONG BpId);

#ifdef __cplusplus
}
#endif
