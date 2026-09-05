/*!
    @file       NpPseudoDbg.cpp

    @brief      P2 伪附加状态机（LSTAR 分发器主路径）。

    @details    DebugActiveProcess / WaitForDebugEvent / DebugContinue /
                RemoveProcessDebug 的完整语义重实现：
                - 伪句柄只存在于自建会话表，从不进 Ob 句柄表；
                - 事件队列 = 链表 + KEVENT，Wait 阻塞在调试器线程上下文；
                - 事件内 hProcess/hThread 为调试器进程真实句柄
                  （ObOpenObjectByPointer）；
                - LOAD_DLL 的 hFile 在调试器上下文 ZwOpenFile；
                - 断点命中（VMEXIT 高 IRQL）只入队 + KeSetEvent，
                  不做任何 Guest 异常注入。
 */
#define POOL_NX_OPTIN 1
#include "NpPseudoDbg.h"
#include "NpBreakPoint.h"
#include "NpProcessHide.h"
#include "NpMemAccess.h"
#include "NpLog.h"
#include "NpSvm.h"

// WDK 内核头不引入 ZwQuerySystemInformation / PsGetProcessPeb 声明。
#define SystemProcessInformation 5
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);
extern "C" PVOID PsGetProcessPeb(PEPROCESS Process);

// SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION 关键偏移（x64，
// 对照 x64dbg src/dbg/ntdll/ntdll.h 的权威布局）。
#define NP_SPI_OFFSET_PID       0x50
#define NP_SPI_OFFSET_THREADS   0x100
#define NP_STI_SIZE             0x50
#define NP_STI_OFFSET_START     0x20
#define NP_STI_OFFSET_CLIENTID  0x28
#define NP_STI_OFFSET_TID       0x30
#define NP_PSEUDO_MAX_THREADS   64

typedef struct _NP_THREAD_ENTRY {
    ULONG ThreadId;
    ULONG_PTR StartAddress;
} NP_THREAD_ENTRY;

// ThreadBasicInformation 最小镜像（TEB 基址位于 +0x08）。
typedef struct _NP_THREAD_BASIC_INFO {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR ClientIdProcess;
    ULONG_PTR ClientIdThread;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} NP_THREAD_BASIC_INFO;

extern "C" NTSTATUS NTAPI ZwQueryInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength);

typedef struct _NP_PSEUDO_EVENT {
    LIST_ENTRY Link;
    ULONG Code;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG_PTR Address;      // 异常地址 / 模块基址 / 进程映像基址
    ULONG_PTR Param;        // BpId / 模块大小
    ULONG_PTR ImageNameVa;  // 目标进程内 UNICODE_STRING Buffer VA（LOAD_DLL）
    ULONG_PTR StartAddress; // CREATE_PROCESS / CREATE_THREAD lpStartAddress
    ULONG_PTR ThreadLocalBase; // TEB 基址
    ULONG FirstChance;      // EXCEPTION dwFirstChance
    WCHAR ModulePath[256];  // LOAD_DLL 完整路径（hFile 打开用）
} NP_PSEUDO_EVENT;

typedef struct _NP_PSEUDO_SESSION {
    LIST_ENTRY Link;
    ULONG SessionId;
    ULONG TargetPid;
    ULONG DebuggerPid;
    KEVENT Event;
    KSPIN_LOCK Lock;
    LIST_ENTRY EventQueue;
    ULONG EventCount;
    BOOLEAN Detached;
    ULONG LastBpId;
    ULONG_PTR LastBpVa;
} NP_PSEUDO_SESSION;

static LIST_ENTRY g_Sessions;
static LIST_ENTRY g_ZombieSessions;     // 已分离但可能仍有 Wait 阻塞者的会话
static KSPIN_LOCK g_SessLock;
static ULONG g_NextId = 1;

static NP_PSEUDO_SESSION *FindSession(ULONG TargetPid, ULONG DebuggerPid)
{
    for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
    {
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        if (s->TargetPid == TargetPid && s->DebuggerPid == DebuggerPid &&
            !s->Detached)
        {
            return s;
        }
    }
    return nullptr;
}

static NP_PSEUDO_SESSION *FindSessionById(ULONG SessionId)
{
    for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
    {
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        if (s->SessionId == SessionId) return s;
    }
    for (PLIST_ENTRY e = g_ZombieSessions.Flink;
         e != &g_ZombieSessions; e = e->Flink)
    {
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        if (s->SessionId == SessionId) return s;
    }
    return nullptr;
}

BOOLEAN NpPseudoDbgFindByDebugger(ULONG DebuggerPid,
                                  PULONG OutTargetPid,
                                  PULONG OutSessionId)
{
    if (DebuggerPid == 0) return FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
    {
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        if (!s->Detached && s->DebuggerPid == DebuggerPid)
        {
            if (OutTargetPid) *OutTargetPid = s->TargetPid;
            if (OutSessionId) *OutSessionId = s->SessionId;
            KeReleaseSpinLock(&g_SessLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_SessLock, irql);
    return FALSE;
}

NTSTATUS NpPseudoDbgInitialize(void)
{
    InitializeListHead(&g_Sessions);
    InitializeListHead(&g_ZombieSessions);
    KeInitializeSpinLock(&g_SessLock);
    g_NextId = 1;
    return STATUS_SUCCESS;
}

static VOID FreeSessionEvents(NP_PSEUDO_SESSION *s)
{
    while (!IsListEmpty(&s->EventQueue))
    {
        PLIST_ENTRY q = RemoveHeadList(&s->EventQueue);
        ExFreePoolWithTag(CONTAINING_RECORD(q, NP_PSEUDO_EVENT, Link), 'DbPs');
    }
    s->EventCount = 0;
}

void NpPseudoDbgTeardown(void)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    while (!IsListEmpty(&g_Sessions))
    {
        PLIST_ENTRY e = RemoveHeadList(&g_Sessions);
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        FreeSessionEvents(s);
        ExFreePoolWithTag(s, 'DbPs');
    }
    while (!IsListEmpty(&g_ZombieSessions))
    {
        PLIST_ENTRY e = RemoveHeadList(&g_ZombieSessions);
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        FreeSessionEvents(s);
        ExFreePoolWithTag(s, 'DbPs');
    }
    KeReleaseSpinLock(&g_SessLock, irql);
}

NTSTATUS NpPseudoDbgCreateSession(ULONG TargetPid, ULONG DebuggerPid,
                                  ULONG *OutSessionId)
{
    if (TargetPid == 0 || DebuggerPid == 0) return STATUS_INVALID_PARAMETER;

    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    if (FindSession(TargetPid, DebuggerPid) != nullptr)
    {
        KeReleaseSpinLock(&g_SessLock, irql);
        return STATUS_ALREADY_REGISTERED;
    }
    KeReleaseSpinLock(&g_SessLock, irql);

    NP_PSEUDO_SESSION *s = (NP_PSEUDO_SESSION *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*s), 'DbPs');
    if (!s) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(s, sizeof(*s));
    s->SessionId = InterlockedIncrement((LONG *)&g_NextId);
    s->TargetPid = TargetPid;
    s->DebuggerPid = DebuggerPid;
    KeInitializeEvent(&s->Event, SynchronizationEvent, FALSE);
    KeInitializeSpinLock(&s->Lock);
    InitializeListHead(&s->EventQueue);

    KeAcquireSpinLock(&g_SessLock, &irql);
    InsertTailList(&g_Sessions, &s->Link);
    KeReleaseSpinLock(&g_SessLock, irql);

    if (OutSessionId) *OutSessionId = s->SessionId;
    NpHvLogPrint("[pseudo] create session %lu tgt=%lu dbg=%lu\n",
                 s->SessionId, TargetPid, DebuggerPid);
    return STATUS_SUCCESS;
}

NTSTATUS NpPseudoDbgRemoveSession(ULONG SessionId)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSessionById(SessionId);
    if (s == nullptr)
    {
        KeReleaseSpinLock(&g_SessLock, irql);
        return STATUS_NOT_FOUND;
    }
    if (s->Detached)
    {
        KeReleaseSpinLock(&g_SessLock, irql);
        return STATUS_SUCCESS;
    }
    RemoveEntryList(&s->Link);
    s->Detached = TRUE;
    InsertTailList(&g_ZombieSessions, &s->Link);
    KeSetEvent(&s->Event, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&g_SessLock, irql);
    NpHvLogPrint("[pseudo] remove session %lu tgt=%lu\n",
                 SessionId, s->TargetPid);
    return STATUS_SUCCESS;
}

NTSTATUS NpPseudoDbgDetachByTarget(ULONG TargetPid, ULONG DebuggerPid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSession(TargetPid, DebuggerPid);
    if (s == nullptr)
    {
        KeReleaseSpinLock(&g_SessLock, irql);
        return STATUS_NOT_FOUND;
    }
    RemoveEntryList(&s->Link);
    s->Detached = TRUE;
    InsertTailList(&g_ZombieSessions, &s->Link);
    KeSetEvent(&s->Event, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&g_SessLock, irql);
    NpProcessHideRemovePid(DebuggerPid);
    // 调试器分离/退出时恢复所有被 HALT 钉住的断点线程，避免目标进程
    // 卡在 #NPF 忙循环导致关闭/终止时看门狗蓝屏。
    NpBreakPointContinue(0);
    // 分离时摘除该目标的用户态断点并解锁 MDL（防 0x76 锁页蓝屏）。
    NpBreakPointUninstallByPid(TargetPid);
    NpHvLogPrint("[pseudo] detach tgt=%lu dbg=%lu\n", TargetPid, DebuggerPid);
    return STATUS_SUCCESS;
}

BOOLEAN NpPseudoDbgIsSessionTarget(ULONG TargetPid, ULONG DebuggerPid)
{
    KIRQL irql;
    BOOLEAN hit = FALSE;
    KeAcquireSpinLock(&g_SessLock, &irql);
    hit = (FindSession(TargetPid, DebuggerPid) != nullptr);
    KeReleaseSpinLock(&g_SessLock, irql);
    return hit;
}

BOOLEAN NpPseudoDbgIsTargetAttached(ULONG TargetPid)
{
    KIRQL irql;
    BOOLEAN hit = FALSE;
    KeAcquireSpinLock(&g_SessLock, &irql);
    for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
    {
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        if (s->TargetPid == TargetPid && !s->Detached) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&g_SessLock, irql);
    return hit;
}

ULONG NpPseudoDbgGetSessionCount(void)
{
    KIRQL irql;
    ULONG n = 0;
    KeAcquireSpinLock(&g_SessLock, &irql);
    for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
        n++;
    KeReleaseSpinLock(&g_SessLock, irql);
    return n;
}

//
// ============================ 事件队列 ============================
//

static NTSTATUS EnqueueEvent(NP_PSEUDO_SESSION *s, const NP_PSEUDO_EVENT *ev)
{
    NP_PSEUDO_EVENT *e = (NP_PSEUDO_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*e), 'DbPs');
    if (!e) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(e, ev, sizeof(*e));

    KIRQL irql;
    KeAcquireSpinLock(&s->Lock, &irql);
    if (s->EventCount >= NPHV_PSEUDO_MAX_EVENTS)
    {
        KeReleaseSpinLock(&s->Lock, irql);
        ExFreePoolWithTag(e, 'DbPs');
        return STATUS_BUFFER_OVERFLOW;
    }
    InsertTailList(&s->EventQueue, &e->Link);
    s->EventCount++;
    KeSetEvent(&s->Event, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&s->Lock, irql);
    return STATUS_SUCCESS;
}

VOID NpPseudoDbgQueueBpEvent(ULONG TargetPid, ULONG_PTR BpVa, ULONG Tid,
                             ULONG BpId)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    for (PLIST_ENTRY e = g_Sessions.Flink; e != &g_Sessions; e = e->Flink)
    {
        NP_PSEUDO_SESSION *s = CONTAINING_RECORD(e, NP_PSEUDO_SESSION, Link);
        if (s->TargetPid == TargetPid && !s->Detached)
        {
            // 同一目标可能存在多个会话（NpHvCtl 伪附加 + x64dbg DAP），
            // 断点事件必须入队到全部活动会话，否则只有第一个会话能收到。
            NP_PSEUDO_EVENT ev;
            RtlZeroMemory(&ev, sizeof(ev));
            ev.Code = NPHV_DEBUG_EVENT_EXCEPTION;
            ev.ProcessId = TargetPid;
            ev.ThreadId = Tid;
            ev.Address = BpVa;
            ev.Param = BpId;
            ev.FirstChance = 1;
            s->LastBpId = BpId;
            s->LastBpVa = BpVa;
            NTSTATUS qs = EnqueueEvent(s, &ev);
            NpHvLogPrint("[pseudo] bp queued sess=%lu tgt=%lu va=%p "
                         "tid=%lu id=%lu status=0x%08x\n",
                         s->SessionId, TargetPid, (PVOID)BpVa, Tid, BpId, qs);
        }
    }
    KeReleaseSpinLock(&g_SessLock, irql);
}

//
// ============================ 句柄/DEBUG_EVENT 构造 ============================
//

static NTSTATUS OpenProcessHandleUser(ULONG Pid, PHANDLE Out)
{
    PEPROCESS p = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId(ULongToHandle(Pid), &p);
    if (!NT_SUCCESS(st) || p == nullptr) return st ? st : STATUS_NOT_FOUND;
    st = ObOpenObjectByPointer(p, 0, nullptr, PROCESS_ALL_ACCESS,
                               *PsProcessType, UserMode, Out);
    ObDereferenceObject(p);
    return st;
}

static NTSTATUS OpenThreadHandleUser(ULONG Tid, PHANDLE Out)
{
    PETHREAD t = nullptr;
    NTSTATUS st = PsLookupThreadByThreadId(ULongToHandle(Tid), &t);
    if (!NT_SUCCESS(st) || t == nullptr) return st ? st : STATUS_NOT_FOUND;
    st = ObOpenObjectByPointer(t, 0, nullptr, THREAD_ALL_ACCESS,
                               *PsThreadType, UserMode, Out);
    ObDereferenceObject(t);
    return st;
}

static NTSTATUS GetThreadTeb(HANDLE hThread, PULONG_PTR Out)
{
    if (hThread == nullptr || Out == nullptr) return STATUS_INVALID_PARAMETER;
    NP_THREAD_BASIC_INFO tbi;
    RtlZeroMemory(&tbi, sizeof(tbi));
    NTSTATUS st = ZwQueryInformationThread(hThread, 0 /* ThreadBasicInformation */,
                                           &tbi, sizeof(tbi), nullptr);
    if (NT_SUCCESS(st) && tbi.TebBaseAddress != nullptr)
    {
        *Out = (ULONG_PTR)tbi.TebBaseAddress;
        return STATUS_SUCCESS;
    }
    return st;
}

// PEB 给的是 Win32 路径（C:\...），ZwOpenFile 需要 NT 路径（\??\C:\...）。
static NTSTATUS OpenModuleFileHandle(PCWSTR Path, PHANDLE Out)
{
    if (Path == nullptr || Path[0] == 0) return STATUS_INVALID_PARAMETER;
    WCHAR ntPath[320];
    if (Path[0] == L'\\' && Path[1] == L'\\')
    {
        // UNC：\\server\share → \??\UNC\server\share
        RtlStringCchPrintfW(ntPath, RTL_NUMBER_OF(ntPath),
                            L"\\??\\UNC%s", Path + 1);
    }
    else
    {
        RtlStringCchPrintfW(ntPath, RTL_NUMBER_OF(ntPath),
                            L"\\??\\%s", Path);
    }
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    RtlInitUnicodeString(&name, ntPath);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE,
                               nullptr, nullptr);
    return ZwOpenFile(Out, FILE_READ_DATA | FILE_READ_ATTRIBUTES, &oa, &iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
}

static NTSTATUS BuildDebugEvent(const NP_PSEUDO_EVENT *ev, PNPHV_DEBUG_EVENT Out)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->dwDebugEventCode = ev->Code;
    Out->dwProcessId = ev->ProcessId;
    Out->dwThreadId = ev->ThreadId;

    // 一次性诊断：只看 CREATE_PROCESS / 首个 LOAD_DLL 的句柄与基址结果。
    static volatile LONG s_diagShown = 0;

    switch (ev->Code)
    {
    case NPHV_DEBUG_EVENT_EXCEPTION:
        Out->u.Exception.ExceptionCode = NPHV_EXCEPTION_BREAKPOINT;
        Out->u.Exception.ExceptionFlags = 0;
        Out->u.Exception.ExceptionRecord = 0;
        Out->u.Exception.ExceptionAddress = ev->Address;
        Out->u.Exception.NumberParameters = 0;
        // 该版本 DEBUG_EVENT：0x18 头 + 14 参数 EXCEPTION_RECORD(0x90)，
        // dwFirstChance 落在 0xA8（写 0xB0 会越界污染 TerminateDBGEvent，
        // 导致 x64dbg 既不暂停也不继续）。按实测偏移直接写 0xA8。
        *(volatile ULONG *)((PUCHAR)Out + 0xA8) = ev->FirstChance ? 1 : 0;
        break;
    case NPHV_DEBUG_EVENT_CREATE_PROCESS:
        Out->u.CreateProcessInfo.lpBaseOfImage = ev->Address;
        Out->u.CreateProcessInfo.lpStartAddress = ev->StartAddress;
        Out->u.CreateProcessInfo.lpThreadLocalBase = ev->ThreadLocalBase;
        Out->u.CreateProcessInfo.lpImageName = ev->ImageNameVa;
        Out->u.CreateProcessInfo.fUnicode = TRUE;
        OpenProcessHandleUser(ev->ProcessId, (PHANDLE)&Out->u.CreateProcessInfo.hProcess);
        if (ev->ThreadId != 0)
        {
            OpenThreadHandleUser(ev->ThreadId, (PHANDLE)&Out->u.CreateProcessInfo.hThread);
            GetThreadTeb((HANDLE)Out->u.CreateProcessInfo.hThread,
                         &Out->u.CreateProcessInfo.lpThreadLocalBase);
        }
        if (ev->ModulePath[0] != 0)
            OpenModuleFileHandle(ev->ModulePath,
                                 (PHANDLE)&Out->u.CreateProcessInfo.hFile);
        if (InterlockedCompareExchange(&s_diagShown, 1, 0) == 0)
        {
            NpHvLogPrint("[pseudo] CREATE_PROCESS base=%p hProc=%p hThread=%p "
                         "hFile=%p start=%p teb=%p\n",
                         (PVOID)Out->u.CreateProcessInfo.lpBaseOfImage,
                         (PVOID)Out->u.CreateProcessInfo.hProcess,
                         (PVOID)Out->u.CreateProcessInfo.hThread,
                         (PVOID)Out->u.CreateProcessInfo.hFile,
                         (PVOID)Out->u.CreateProcessInfo.lpStartAddress,
                         (PVOID)Out->u.CreateProcessInfo.lpThreadLocalBase);
        }
        break;
    case NPHV_DEBUG_EVENT_CREATE_THREAD:
        Out->u.CreateThread.lpStartAddress = ev->StartAddress;
        Out->u.CreateThread.lpThreadLocalBase = ev->ThreadLocalBase;
        if (ev->ThreadId != 0)
        {
            OpenThreadHandleUser(ev->ThreadId, (PHANDLE)&Out->u.CreateThread.hThread);
            GetThreadTeb((HANDLE)Out->u.CreateThread.hThread,
                         &Out->u.CreateThread.lpThreadLocalBase);
        }
        break;
    case NPHV_DEBUG_EVENT_LOAD_DLL:
        Out->u.LoadDll.lpBaseOfDll = ev->Address;
        Out->u.LoadDll.dwDebugInfoFileOffset = 0;
        Out->u.LoadDll.nDebugInfoSize = (ULONG)ev->Param;
        Out->u.LoadDll.lpImageName = ev->ImageNameVa;
        Out->u.LoadDll.fUnicode = TRUE;
        OpenModuleFileHandle(ev->ModulePath, (PHANDLE)&Out->u.LoadDll.hFile);
        if (InterlockedCompareExchange(&s_diagShown, 2, 0) == 0)
        {
            NpHvLogPrint("[pseudo] LOAD_DLL base=%p hFile=%p path=%ls\n",
                         (PVOID)Out->u.LoadDll.lpBaseOfDll,
                         (PVOID)Out->u.LoadDll.hFile,
                         ev->ModulePath);
        }
        break;
    default:
        break;
    }
    return STATUS_SUCCESS;
}

//
// ============================ Wait / Continue ============================
//

NTSTATUS NpPseudoDbgWaitEvent(ULONG TargetPid, ULONG DebuggerPid,
                              BOOLEAN Alertable, PLARGE_INTEGER Timeout,
                              PVOID UserEventOut, ULONG EventSize)
{
    KIRQL irql;
    NP_PSEUDO_SESSION *s = nullptr;

    KeAcquireSpinLock(&g_SessLock, &irql);
    s = FindSession(TargetPid, DebuggerPid);
    KeReleaseSpinLock(&g_SessLock, irql);
    if (s == nullptr)
    {
        NpHvLogPrint("[pseudo] wait: session not found tgt=%lu dbg=%lu\n",
                     TargetPid, DebuggerPid);
        return STATUS_INVALID_CID;
    }

    // 用户缓冲是真实 DEBUG_EVENT（x64 = 0xB0：0x10 头 + 0xA0 union）。
    // NtWaitForDebugEventEx 若显式传入更小的 size，按调用方大小复制。
    if (EventSize == 0) EventSize = (ULONG)sizeof(NPHV_DEBUG_EVENT);
    if (EventSize > sizeof(NPHV_DEBUG_EVENT))
        EventSize = (ULONG)sizeof(NPHV_DEBUG_EVENT);
    NpHvLogPrint("[pseudo] wait sess=%lu tgt=%lu dbg=%lu size=%lu\n",
                 s->SessionId, TargetPid, DebuggerPid, EventSize);

    // 阻塞调试器线程直到事件就绪/超时/分离。
    NTSTATUS waitSt = KeWaitForSingleObject(&s->Event, Executive, KernelMode,
                                            Alertable, Timeout);
    if (waitSt == STATUS_TIMEOUT) return STATUS_TIMEOUT;

    KeAcquireSpinLock(&s->Lock, &irql);
    if (IsListEmpty(&s->EventQueue))
    {
        KeReleaseSpinLock(&s->Lock, irql);
        return s->Detached ? STATUS_PROCESS_IS_TERMINATING : STATUS_TIMEOUT;
    }
    PLIST_ENTRY q = RemoveHeadList(&s->EventQueue);
    s->EventCount--;
    NP_PSEUDO_EVENT *ev = CONTAINING_RECORD(q, NP_PSEUDO_EVENT, Link);
    // SynchronizationEvent 自动复位：快照一次入队多个事件时，多次
    // KeSetEvent 只留一个信号；取走一个后若还有剩余，必须重新置位，
    // 否则调试器第二次 Wait 永久阻塞。
    if (s->EventCount > 0)
        KeSetEvent(&s->Event, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&s->Lock, irql);
    NpHvLogPrint("[pseudo] wait event sess=%lu code=%lu pid=%lu tid=%lu "
                 "addr=%p\n",
                 s->SessionId, ev->Code, ev->ProcessId, ev->ThreadId,
                 (PVOID)ev->Address);

    // 目标 x64dbg 把 EXCEPTION 联合体从 0x18 起解析，dwFirstChance 在
    // 0xA8（0x18 + 0x90）；复制 0xB0，避免越界写调用方。
    UCHAR outBuf[sizeof(NPHV_DEBUG_EVENT)];
    RtlZeroMemory(outBuf, sizeof(outBuf));
    NPHV_DEBUG_EVENT *out = reinterpret_cast<NPHV_DEBUG_EVENT *>(outBuf);
    BuildDebugEvent(ev, out);
    ULONG copySize = (ev->Code == NPHV_DEBUG_EVENT_EXCEPTION)
                         ? 0xB0
                         : 0xB0;
    if (EventSize != 0 && EventSize < copySize)
    {
        copySize = EventSize;
    }
    ExFreePoolWithTag(ev, 'DbPs');

    // 发送侧诊断：打印前几次事件的原始字段，用于和 x64dbg 收到的对照。
    static volatile LONG s_sendDiag = 0;
    if (InterlockedIncrement(&s_sendDiag) <= 12)
    {
        PUCHAR p = outBuf;
        NpHvLogPrint("[pseudo] send sess=%lu code=%lu copy=%lu p10=%016llX "
                     "p18=%016llX p20=%016llX p28=%016llX p30=%016llX "
                     "pA8=%08X\n",
                     s->SessionId, out->dwDebugEventCode, copySize,
                     *(unsigned long long *)(p + 0x10),
                     *(unsigned long long *)(p + 0x18),
                     *(unsigned long long *)(p + 0x20),
                     *(unsigned long long *)(p + 0x28),
                     *(unsigned long long *)(p + 0x30),
                     *(unsigned int *)(p + 0xA8));
    }

    NTSTATUS copySt = NpMemAccessCopyToUser((ULONG_PTR)UserEventOut,
                                            outBuf, copySize);
    static volatile LONG s_deliverDiag = 0;
    if (InterlockedIncrement(&s_deliverDiag) <= 16)
    {
        NpHvLogPrint("[pseudo] wait delivered sess=%lu copy=%lu "
                     "status=0x%08x\n",
                     s->SessionId, copySize, copySt);
    }
    return copySt;
}

NTSTATUS NpPseudoDbgContinue(ULONG TargetPid, ULONG DebuggerPid,
                             ULONG ContinueStatus)
{
    UNREFERENCED_PARAMETER(ContinueStatus);
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSession(TargetPid, DebuggerPid);
    if (s == nullptr)
    {
        KeReleaseSpinLock(&g_SessLock, irql);
        return STATUS_INVALID_CID;
    }
    ULONG bpId = s->LastBpId;
    s->LastBpId = 0;
    s->LastBpVa = 0;
    KeReleaseSpinLock(&g_SessLock, irql);

    if (bpId != 0)
    {
        NpBreakPointContinue(bpId);
    }
    return STATUS_SUCCESS;
}

NTSTATUS NpPseudoDbgWaitEventById(ULONG SessionId, PVOID UserEventOut,
                                  ULONG EventSize)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSessionById(SessionId);
    ULONG target = s ? s->TargetPid : 0;
    ULONG debugger = s ? s->DebuggerPid : 0;
    KeReleaseSpinLock(&g_SessLock, irql);
    if (s == nullptr) return STATUS_NOT_FOUND;
    return NpPseudoDbgWaitEvent(target, debugger, FALSE, nullptr,
                                UserEventOut, EventSize);
}

NTSTATUS NpPseudoDbgWaitReadyById(ULONG SessionId)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSessionById(SessionId);
    KeReleaseSpinLock(&g_SessLock, irql);
    if (s == nullptr) return STATUS_NOT_FOUND;

    LARGE_INTEGER to;
    to.QuadPart = -10000LL * 5000;      // 5 秒
    NTSTATUS st = KeWaitForSingleObject(&s->Event, Executive, KernelMode,
                                        FALSE, &to);
    if (st == STATUS_TIMEOUT) return STATUS_TIMEOUT;
    return STATUS_SUCCESS;
}

NTSTATUS NpPseudoDbgContinueById(ULONG SessionId, ULONG ContinueStatus)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSessionById(SessionId);
    ULONG target = s ? s->TargetPid : 0;
    ULONG debugger = s ? s->DebuggerPid : 0;
    KeReleaseSpinLock(&g_SessLock, irql);
    if (s == nullptr) return STATUS_NOT_FOUND;
    return NpPseudoDbgContinue(target, debugger, ContinueStatus);
}

BOOLEAN NpPseudoDbgGetSessionInfo(ULONG SessionId, PULONG TargetPid,
                                  PULONG DebuggerPid, PULONG EventCount)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SessLock, &irql);
    NP_PSEUDO_SESSION *s = FindSessionById(SessionId);
    if (s == nullptr)
    {
        KeReleaseSpinLock(&g_SessLock, irql);
        return FALSE;
    }
    if (TargetPid) *TargetPid = s->TargetPid;
    if (DebuggerPid) *DebuggerPid = s->DebuggerPid;
    if (EventCount) *EventCount = s->EventCount;
    KeReleaseSpinLock(&g_SessLock, irql);
    return TRUE;
}

//
// ============================ 快照 ============================
//

// 通过 ZwQuerySystemInformation(SystemProcessInformation) 枚举目标进程全部线程。
// x64 布局：进程条目 PID @+0x50，Threads @+0x100；
// 线程条目 StartAddress @+0x20，ClientId.UniqueThread @+0x30，条目大小 0x50。
static ULONG EnumerateThreads(ULONG TargetPid, NP_THREAD_ENTRY *Entries,
                              ULONG MaxEntries)
{
    ULONG need = 0x10000;
    PVOID buf = nullptr;
    ULONG count = 0;
    for (ULONG round = 0; round < 8; round++)
    {
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'DbPs');
        if (!buf) return 0;
        ULONG returned = 0;
        NTSTATUS st = ZwQuerySystemInformation(SystemProcessInformation,
                                               buf, need, &returned);
        if (st == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(buf, 'DbPs');
            need = returned ? returned + 0x1000 : need * 2;
            continue;
        }
        if (!NT_SUCCESS(st))
        {
            ExFreePoolWithTag(buf, 'DbPs');
            return 0;
        }

        PUCHAR p = (PUCHAR)buf;
        for (;;)
        {
            ULONG next = *(PULONG)p;
            HANDLE pid = *(PHANDLE)(p + NP_SPI_OFFSET_PID);
            if (pid == ULongToHandle(TargetPid))
            {
                ULONG nThreads = *(PULONG)(p + 0x04);
                PUCHAR t = p + NP_SPI_OFFSET_THREADS;
                for (ULONG i = 0; i < nThreads && count < MaxEntries; i++)
                {
                    Entries[count].ThreadId = (ULONG)(ULONG_PTR)
                        (*(PHANDLE)(t + i * NP_STI_SIZE + NP_STI_OFFSET_TID));
                    Entries[count].StartAddress =
                        *(ULONG_PTR *)(t + i * NP_STI_SIZE +
                                       NP_STI_OFFSET_START);
                    count++;
                }
                ExFreePoolWithTag(buf, 'DbPs');
                return count;
            }
            if (next == 0) break;
            p += next;
        }
        ExFreePoolWithTag(buf, 'DbPs');
        return 0;
    }
    if (buf) ExFreePoolWithTag(buf, 'DbPs');
    return 0;
}

// 主模块入口点：PE 头 e_lfanew → NT 头 → OptionalHeader.AddressOfEntryPoint。
static NTSTATUS GetImageEntryPoint(ULONG TargetPid, ULONG_PTR ImageBase,
                                   PULONG_PTR Out)
{
    if (ImageBase == 0 || Out == nullptr) return STATUS_INVALID_PARAMETER;
    ULONG got = 0;
    ULONG e_lfanew = 0;
    if (!NT_SUCCESS(NpMemAccessRead(TargetPid, ImageBase + 0x3C,
                                    &e_lfanew, sizeof(e_lfanew), &got)) ||
        got != sizeof(e_lfanew) || e_lfanew == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }
    ULONG_PTR nt = ImageBase + e_lfanew;
    USHORT magic = 0;
    if (!NT_SUCCESS(NpMemAccessRead(TargetPid, nt + 0x18,
                                    &magic, sizeof(magic), &got)) ||
        got != sizeof(magic) || magic != 0x20B)   // PE32+
    {
        return STATUS_UNSUCCESSFUL;
    }
    ULONG entryRva = 0;
    if (!NT_SUCCESS(NpMemAccessRead(TargetPid, nt + 0x28,
                                    &entryRva, sizeof(entryRva), &got)) ||
        got != sizeof(entryRva) || entryRva == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }
    *Out = ImageBase + entryRva;
    return STATUS_SUCCESS;
}

NTSTATUS NpPseudoDbgSnapshot(ULONG TargetPid, ULONG DebuggerPid)
{
    KIRQL irql;
    NP_PSEUDO_SESSION *s = nullptr;
    KeAcquireSpinLock(&g_SessLock, &irql);
    s = FindSession(TargetPid, DebuggerPid);
    KeReleaseSpinLock(&g_SessLock, irql);
    if (s == nullptr) return STATUS_INVALID_CID;

    PEPROCESS proc = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(TargetPid),
                                               &proc)) || proc == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    PVOID peb = PsGetProcessPeb(proc);
    ULONG_PTR imageBase = 0;
    NP_THREAD_ENTRY threads[NP_PSEUDO_MAX_THREADS];
    RtlZeroMemory(threads, sizeof(threads));
    ULONG threadCount = EnumerateThreads(TargetPid, threads,
                                         NP_PSEUDO_MAX_THREADS);
    ULONG mainTid = threadCount != 0 ? threads[0].ThreadId : 0;
    NpHvLogPrint("[pseudo] snapshot tgt=%lu threads=%lu main=%lu\n",
                 TargetPid, threadCount, mainTid);
    if (peb != nullptr)
    {
        ULONG got = 0;
        if (NT_SUCCESS(NpMemAccessRead(TargetPid, (ULONG_PTR)peb + 0x10,
                                       &imageBase, sizeof(imageBase), &got)) &&
            got == sizeof(imageBase))
        {
            NpHvLogPrint("[pseudo] snapshot imageBase=%p peb=%p\n",
                         (PVOID)imageBase, peb);
        }
        else
        {
            NpHvLogPrint("[pseudo] snapshot imageBase read FAILED peb=%p\n", peb);
        }
    }
    else
    {
        NpHvLogPrint("[pseudo] snapshot peb=null\n");
    }

    // 映像路径：PEB.ProcessParameters.ImagePathName（CREATE_PROCESS hFile 用）。
    WCHAR imagePath[256];
    imagePath[0] = 0;
    if (peb != nullptr)
    {
        ULONG_PTR params = 0;
        ULONG got = 0;
        if (NT_SUCCESS(NpMemAccessRead(TargetPid, (ULONG_PTR)peb + 0x20,
                                       &params, sizeof(params), &got)) &&
            got == sizeof(params) && params != 0)
        {
            USHORT len = 0;
            ULONG_PTR nameBuf = 0;
            if (NT_SUCCESS(NpMemAccessRead(TargetPid, params + 0x60,
                                           &len, sizeof(len), &got)) &&
                NT_SUCCESS(NpMemAccessRead(TargetPid, params + 0x68,
                                           &nameBuf, sizeof(nameBuf), &got)) &&
                nameBuf != 0 && len >= 2 && len < sizeof(imagePath))
            {
                if (NT_SUCCESS(NpMemAccessRead(TargetPid, nameBuf,
                                               imagePath, len, &got)))
                {
                    imagePath[len / sizeof(WCHAR)] = 0;
                }
            }
        }
    }

    // CREATE_PROCESS
    {
        NP_PSEUDO_EVENT ev;
        RtlZeroMemory(&ev, sizeof(ev));
        ev.Code = NPHV_DEBUG_EVENT_CREATE_PROCESS;
        ev.ProcessId = TargetPid;
        ev.ThreadId = mainTid;
        if (threadCount != 0) ev.StartAddress = threads[0].StartAddress;
        if (peb != nullptr)
        {
            ULONG got = 0;
            if (NT_SUCCESS(NpMemAccessRead(TargetPid,
                                           (ULONG_PTR)peb + 0x10,
                                           &imageBase, sizeof(imageBase),
                                           &got)) && got == sizeof(imageBase))
            {
                ev.Address = imageBase;
            }
        }
        RtlCopyMemory(ev.ModulePath, imagePath, sizeof(ev.ModulePath));
        EnqueueEvent(s, &ev);
    }

    // CREATE_THREAD：附加时其余现存线程（含 hThread / 起始地址 / TEB）。
    for (ULONG i = 1; i < threadCount; i++)
    {
        NP_PSEUDO_EVENT ev;
        RtlZeroMemory(&ev, sizeof(ev));
        ev.Code = NPHV_DEBUG_EVENT_CREATE_THREAD;
        ev.ProcessId = TargetPid;
        ev.ThreadId = threads[i].ThreadId;
        ev.StartAddress = threads[i].StartAddress;
        EnqueueEvent(s, &ev);
    }

    // LOAD_DLL：PEB.Ldr 模块链表。
    // 实测目标 x64dbg 会把伪 LOAD_DLL 事件误读成异常（模块基址出现在
    // ExceptionCode/Flags），先跳过由 x64dbg 自行枚举模块；需要时可重新
    // 打开此宏并适配其真实布局。
#if !NP_PSEUDO_SKIP_LOAD_DLL
    if (peb != nullptr)
    {
        ULONG_PTR ldr = 0;
        ULONG got = 0;
        if (NT_SUCCESS(NpMemAccessRead(TargetPid, (ULONG_PTR)peb + 0x18,
                                       &ldr, sizeof(ldr), &got)) &&
            got == sizeof(ldr) && ldr != 0)
        {
            ULONG_PTR head = ldr + 0x10;
            ULONG_PTR cur = head;
            for (ULONG i = 0; i < NPHV_PSEUDO_MAX_MODULES; i++)
            {
                ULONG_PTR flink = 0;
                if (!NT_SUCCESS(NpMemAccessRead(TargetPid, cur,
                                                &flink, sizeof(flink), &got)) ||
                    got != sizeof(flink))
                {
                    break;
                }
                if (flink == head) break;
                ULONG_PTR entry = flink - 0x00;   // InLoadOrderLinks 在条目头
                ULONG_PTR dllBase = 0, size = 0, nameBuf = 0;
                USHORT nameLen = 0;
                NpMemAccessRead(TargetPid, entry + 0x30, &dllBase,
                                sizeof(dllBase), &got);
                NpMemAccessRead(TargetPid, entry + 0x40, &size,
                                sizeof(size), &got);
                NpMemAccessRead(TargetPid, entry + 0x48, &nameLen,
                                sizeof(nameLen), &got);
                NpMemAccessRead(TargetPid, entry + 0x48 + 0x08, &nameBuf,
                                sizeof(nameBuf), &got);

                NP_PSEUDO_EVENT ev;
                RtlZeroMemory(&ev, sizeof(ev));
                ev.Code = NPHV_DEBUG_EVENT_LOAD_DLL;
                ev.ProcessId = TargetPid;
                ev.ThreadId = mainTid;
                ev.Address = dllBase;
                ev.Param = size;
                ev.ImageNameVa = nameBuf;
                if (nameBuf != 0 && nameLen >= 2 && nameLen < sizeof(ev.ModulePath))
                {
                    NpMemAccessRead(TargetPid, nameBuf, ev.ModulePath,
                                    nameLen, &got);
                    ev.ModulePath[nameLen / sizeof(WCHAR)] = 0;
                }
                EnqueueEvent(s, &ev);
                cur = flink;
            }
        }
    }
#endif

    // 初始断点：附加事件流收尾后让 x64dbg 立即暂停，CPU 视图和断点
    // 立即可用（伪附加没有真实系统断点，需要补一个 EXCEPTION_BREAKPOINT）。
    if (mainTid != 0 && imageBase != 0)
    {
        NP_PSEUDO_EVENT ev;
        RtlZeroMemory(&ev, sizeof(ev));
        ev.Code = NPHV_DEBUG_EVENT_EXCEPTION;
        ev.ProcessId = TargetPid;
        ev.ThreadId = mainTid;
        ev.FirstChance = 1;
        ULONG_PTR entry = 0;
        if (NT_SUCCESS(GetImageEntryPoint(TargetPid, imageBase, &entry)))
        {
            ev.Address = entry;
        }
        else if (threadCount != 0 && threads[0].StartAddress != 0)
        {
            ev.Address = threads[0].StartAddress;
        }
        else
        {
            ev.Address = imageBase;
        }
        NpHvLogPrint("[pseudo] initial bp addr=%p\n", (PVOID)ev.Address);
        EnqueueEvent(s, &ev);
    }
    ObDereferenceObject(proc);
    NpHvLogPrint("[pseudo] snapshot tgt=%lu modules queued\n", TargetPid);
    return STATUS_SUCCESS;
}
