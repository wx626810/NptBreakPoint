#define POOL_NX_OPTIN 1
#include "NptHook.hpp"
#include "NpProcessHide.h"
#include "NpSyscall.h"
#include "NpLstar.h"
#include "NpMemAccess.h"
#include <ntstrsafe.h>

#define NP_PROCESS_HIDE_MAX 16
#define NP_GUARD_MAX 32
#define NP_VIEWER_MAX 8

typedef struct _NP_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved1[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
} NP_SYSTEM_PROCESS_INFORMATION, *PNP_SYSTEM_PROCESS_INFORMATION;
static_assert(FIELD_OFFSET(NP_SYSTEM_PROCESS_INFORMATION, ImageName) == 0x38, "ImageName offset mismatch");

static UNICODE_STRING g_HiddenNames[NP_PROCESS_HIDE_MAX];
static HANDLE g_HiddenPids[NP_PROCESS_HIDE_MAX];
static UNICODE_STRING g_ViewerNames[NP_VIEWER_MAX];     // 查看者豁免名单
static KSPIN_LOCK g_HideLock;
static volatile BOOLEAN g_HideEnabled = FALSE;
static PHOOK_INFO g_HookQSI = nullptr;
static ULONG_PTR g_OrigQSI = 0;
static HANDLE g_GuardTids[NP_GUARD_MAX];
static KSPIN_LOCK g_GuardLock;

static BOOLEAN GuardIsEntered() {
    HANDLE tid = PsGetCurrentThreadId();
    KIRQL irql; BOOLEAN found=FALSE;
    KeAcquireSpinLock(&g_GuardLock, &irql);
    for(int i=0;i<NP_GUARD_MAX;i++) if(g_GuardTids[i]==tid){found=TRUE;break;}
    KeReleaseSpinLock(&g_GuardLock, irql);
    return found;
}
static BOOLEAN GuardEnter() {
    HANDLE tid = PsGetCurrentThreadId();
    KIRQL irql; BOOLEAN ok=FALSE;
    KeAcquireSpinLock(&g_GuardLock, &irql);
    for(int i=0;i<NP_GUARD_MAX;i++) if(g_GuardTids[i]==tid){ok=FALSE; goto out;}
    for(int i=0;i<NP_GUARD_MAX;i++) if(g_GuardTids[i]==0){ g_GuardTids[i]=tid; ok=TRUE; break; }
out:
    KeReleaseSpinLock(&g_GuardLock, irql);
    return ok;
}
static VOID GuardLeave() {
    HANDLE tid = PsGetCurrentThreadId();
    KIRQL irql;
    KeAcquireSpinLock(&g_GuardLock, &irql);
    for(int i=0;i<NP_GUARD_MAX;i++) if(g_GuardTids[i]==tid){ g_GuardTids[i]=0; break; }
    KeReleaseSpinLock(&g_GuardLock, irql);
}
// EPROCESS.ImageFileName 访问（ntoskrnl 导出，部分头文件未声明）
extern "C" PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

static BOOLEAN IsCallerViewer(VOID) {
    //
    // 查看者豁免：名单内进程发起的枚举不过滤。
    // 比较 EPROCESS.ImageFileName（15 字节 ANSI，短名 0 结尾），大小写不敏感。
    // 全程只做非分页内存比较，可在任意 IRQL 调用。
    //
    PCHAR img = PsGetProcessImageFileName(PsGetCurrentProcess());
    if(!img || !img[0]) return FALSE;
    BOOLEAN viewer = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_HideLock, &irql);
    for(int i=0;i<NP_VIEWER_MAX && !viewer;i++){
        UNICODE_STRING* v = &g_ViewerNames[i];
        if(!v->Buffer || !v->Length) continue;
        SIZE_T chars = v->Length / sizeof(wchar_t);
        if(chars == 0 || chars > 15) continue;
        BOOLEAN ok = TRUE;
        for(SIZE_T k=0;k<chars;k++){
            WCHAR w = v->Buffer[k];
            if(w > 0x7F){ ok = FALSE; break; }
            CHAR want = (CHAR)w;
            if(want >= 'a' && want <= 'z') want = (CHAR)(want - 32);
            CHAR have = img[k];
            if(have >= 'a' && have <= 'z') have = (CHAR)(have - 32);
            if(want != have){ ok = FALSE; break; }
        }
        if(ok && chars < 15 && img[chars] != 0) ok = FALSE;   // 整名匹配
        viewer = ok;
    }
    KeReleaseSpinLock(&g_HideLock, irql);
    return viewer;
}
static BOOLEAN IsNameHidden(PUNICODE_STRING Name) {
    //
    // 全程持锁比较（名字最多 16 个、字符串很短，自旋开销微秒级）。
    // 旧实现"持锁拷贝描述符→放锁再用"存在 UAF：并发 Remove/ClearAll
    // 会释放缓冲，比较线程读到已释放池。
    //
    if(!Name || !Name->Buffer || Name->Length==0) return FALSE;
    BOOLEAN hidden = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_HideLock, &irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++){
        UNICODE_STRING* target = &g_HiddenNames[i];
        if(!target->Buffer || !target->Length) continue;
        if(Name->Length >= target->Length){
            UNICODE_STRING suffix; suffix.Length=target->Length; suffix.MaximumLength=target->Length;
            suffix.Buffer=(PWCH)((PUCHAR)Name->Buffer + Name->Length - target->Length);
            if(RtlCompareUnicodeString(&suffix, target, TRUE)==0){ hidden=TRUE; break; }
        }
        if(RtlCompareUnicodeString(Name, target, TRUE)==0){ hidden=TRUE; break; }
    }
    KeReleaseSpinLock(&g_HideLock, irql);
    return hidden;
}

static BOOLEAN IsPidHidden(HANDLE Pid) {
    if (Pid == nullptr) return FALSE;
    KIRQL irql;
    BOOLEAN hidden = FALSE;
    KeAcquireSpinLock(&g_HideLock, &irql);
    for (int i = 0; i < NP_PROCESS_HIDE_MAX; i++) {
        if (g_HiddenPids[i] == Pid) { hidden = TRUE; break; }
    }
    KeReleaseSpinLock(&g_HideLock, irql);
    return hidden;
}
static VOID FilterProcessList(PVOID Buffer, ULONG Length, PULONG RetLen) {
    if(!Buffer) return;
    __try {
        PUCHAR base = (PUCHAR)Buffer;
        PNP_SYSTEM_PROCESS_INFORMATION cur = (PNP_SYSTEM_PROCESS_INFORMATION)base;
        PNP_SYSTEM_PROCESS_INFORMATION prev = nullptr;
        ULONG total = RetLen ? *RetLen : Length;
        ULONG scanCount = 0;
        ULONG hideCount = 0;
        while(cur){
            scanCount++;
            ULONG off = cur->NextEntryOffset;
            // 扫描诊断：第一次成功枚举里打印用户进程 PID/名字长度，
            // 用于确认 x64dbg 条目确实出现在被过滤的缓冲里。
            static volatile LONG s_scanDiag = 0;
            if (InterlockedIncrement(&s_scanDiag) <= 24)
            {
                ULONG pid = (ULONG)(ULONG_PTR)cur->UniqueProcessId;
                if (pid > 1000)
                {
                    NpHvLogPrint("[prochide] scan pid=%lu name_len=%u\n",
                                 pid, cur->ImageName.Length);
                }
            }
            BOOLEAN hide = IsNameHidden(&cur->ImageName) ||
                           IsPidHidden(cur->UniqueProcessId);
            if(hide){
                hideCount++;
                static volatile LONG s_hideDiag = 0;
                if (InterlockedIncrement(&s_hideDiag) <= 8)
                {
                    ULONG pid = (ULONG)(ULONG_PTR)cur->UniqueProcessId;
                    NpHvLogPrint("[prochide] hide entry pid=%lu\n", pid);
                }
                if(prev){
                    if(off==0) prev->NextEntryOffset=0;
                    else prev->NextEntryOffset+=off;
                } else {
                    if(off==0){
                        if(RetLen) *RetLen=0;
                        RtlZeroMemory(base, Length);
                        break;
                    } else {
                        PUCHAR next = base + off;
                        SIZE_T bytesToMove = total - off;
                        RtlMoveMemory(base, next, bytesToMove);
                        RtlZeroMemory(base+bytesToMove, off);
                        if(RetLen) *RetLen-=off;
                        total-=off;
                        cur=(PNP_SYSTEM_PROCESS_INFORMATION)base;
                        continue;
                    }
                }
            } else {
                prev=cur;
            }
            if(off==0) break;
            cur=(PNP_SYSTEM_PROCESS_INFORMATION)((PUCHAR)cur + off);
            if((PUCHAR)cur >= base+total) break;
        }
        static volatile LONG s_filterDiag = 0;
        if (InterlockedIncrement((volatile LONG *)&s_filterDiag) <= 8)
        {
            NpHvLogPrint("[prochide] filter scanned=%lu hidden=%lu "
                         "retlen=%lu\n",
                         scanCount, hideCount,
                         RetLen != nullptr ? *RetLen : total);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER){}
}

// 安全过滤：先把用户缓冲拷到内核临时缓冲，过滤后再拷回，
// 避免直接读写用户页触发 0x50（SMAP/KPTI 环境）。
static VOID FilterProcessListSafe(PVOID UserBuffer, ULONG Length, PULONG UserRetLen) {
    if(!UserBuffer) return;
    ULONG retLen = 0;
    if(UserRetLen != nullptr){
        if(!NT_SUCCESS(NpMemAccessCopyFromUser((ULONG_PTR)UserRetLen,
                                               &retLen, sizeof(retLen))))
            return;
    } else {
        retLen = Length;
    }
    if(retLen == 0 || retLen > 0x40000) return;   // 256KB 上限，防大缓冲分配
    PVOID temp = ExAllocatePool2(POOL_FLAG_NON_PAGED, retLen, 'hQSI');
    if(temp == nullptr) return;
    if(!NT_SUCCESS(NpMemAccessCopyFromUser((ULONG_PTR)UserBuffer, temp, retLen))){
        ExFreePoolWithTag(temp, 'hQSI');
        return;
    }
    ULONG newLen = retLen;
    FilterProcessList(temp, retLen, &newLen);
    if(NT_SUCCESS(NpMemAccessCopyToUser((ULONG_PTR)UserBuffer, temp, retLen))){
        if(UserRetLen != nullptr)
            NpMemAccessCopyToUser((ULONG_PTR)UserRetLen, &newLen, sizeof(newLen));
    }
    ExFreePoolWithTag(temp, 'hQSI');
}
static BOOLEAN NpProcessHideHook(PHOOK_CALL_CONTEXT Ctx){
    ULONG cls = (ULONG)(Ctx->Rcx & 0xFFFFFFFF);
    if(cls != 5 && cls != 57) return FALSE;
    if(!g_HideEnabled) return FALSE;
    if(IsCallerViewer()) return FALSE;      // 查看者（自家调试器）看全量列表
    //
    // IRQL 防御：方案C 下中断可能把 B 态窗口拉长到 ISR/DPC 时长，
    // 若 DPC 路径调用 QSI 会以高 IRQL 进入本回调。FilterProcessList
    // 操作调用者缓冲区且语义为 PASSIVE 级 —— 高 IRQL 一律放行。
    //
    if(KeGetCurrentIrql() >= DISPATCH_LEVEL) return FALSE;
    if(GuardIsEntered()) return FALSE;
    PVOID buf=(PVOID)Ctx->Rdx; ULONG len=(ULONG)Ctx->R8; PULONG retLen=(PULONG)Ctx->R9;
    if(!buf || len==0) return FALSE;
    if(!GuardEnter()) return FALSE;
    typedef NTSTATUS (*PFN_QSI)(ULONG,PVOID,ULONG,PULONG);
    PFN_QSI orig=(PFN_QSI)g_OrigQSI;
    NTSTATUS st=orig(cls,buf,len,retLen);
    GuardLeave();
    if(!NT_SUCCESS(st)){ Ctx->Rax=(ULONG_PTR)st; return TRUE; }
    FilterProcessListSafe(buf,len,retLen);
    Ctx->Rax=(ULONG_PTR)st;
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
NpProcessHideHandleQsiSplit(
    ULONG_PTR InfoClass,
    ULONG_PTR Buffer,
    ULONG_PTR Length,
    ULONG_PTR ReturnLength,
    PULONG_PTR OutStatus)
{
    ULONG cls = (ULONG)(InfoClass & 0xFFFFFFFF);
    if (OutStatus) *OutStatus = (ULONG_PTR)STATUS_UNSUCCESSFUL;

    // 诊断：记录每个 QSI 调用者是否被查看者豁免（定位进程列表缺失）。
    {
        static volatile LONG s_QsiAllDiag = 0;
        if (InterlockedIncrement((volatile LONG *)&s_QsiAllDiag) <= 24)
        {
            PCHAR img = PsGetProcessImageFileName(PsGetCurrentProcess());
            NpHvLogPrint("[prochide] qsi all pid=%lu viewer=%u img=%s "
                         "cls=%lu len=%lu\n",
                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                         IsCallerViewer() ? 1 : 0,
                         img != nullptr ? img : "?",
                         cls, (ULONG)Length);
        }
    }

    if (!g_HideEnabled) return FALSE;
    if (cls != 5 && cls != 57) return FALSE;
    if (IsCallerViewer()) return FALSE;
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) return FALSE;
    if (GuardIsEntered()) return FALSE;
    if (Buffer == 0 || Length == 0) return FALSE;
    if (!GuardEnter()) return FALSE;

    static volatile ULONG s_QsiDiag = 0;
    if (InterlockedIncrement((volatile LONG *)&s_QsiDiag) <= 8)
    {
        NpHvLogPrint("[prochide] qsi split cls=%lu len=%lu caller=%lu\n",
                     cls, (ULONG)Length,
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    }

    typedef NTSTATUS (*PFN_QSI)(ULONG, PVOID, ULONG, PULONG);
    NTSTATUS st = ((PFN_QSI)g_OrigQSI)(cls, (PVOID)Buffer,
                                       (ULONG)Length,
                                       (PULONG)ReturnLength);
    GuardLeave();
    if (!NT_SUCCESS(st))
    {
        if (OutStatus) *OutStatus = (ULONG_PTR)st;
        return TRUE;
    }
    FilterProcessListSafe((PVOID)Buffer, (ULONG)Length, (PULONG)ReturnLength);
    if (s_QsiDiag <= 8)
    {
        NpHvLogPrint("[prochide] qsi split filtered cls=%lu\n", cls);
    }
    if (OutStatus) *OutStatus = (ULONG_PTR)st;
    return TRUE;
}
NTSTATUS NpProcessHideInitialize(VOID){
    RtlZeroMemory(g_HiddenNames,sizeof(g_HiddenNames));
    RtlZeroMemory(g_ViewerNames,sizeof(g_ViewerNames));
    KeInitializeSpinLock(&g_HideLock);
    KeInitializeSpinLock(&g_GuardLock);
    RtlZeroMemory(g_GuardTids,sizeof(g_GuardTids));
    RtlZeroMemory(g_HiddenPids,sizeof(g_HiddenPids));
    g_HideEnabled=FALSE; g_HookQSI=nullptr; g_OrigQSI=0;
    const wchar_t* defaults[]={L"x64dbg.exe",L"x32dbg.exe",L"x64dbg.dll",L"x32bridge.dll",L"TitanEngine.dll",L"scylla_hide.dll"};
    for(int i=0;i<(int)(sizeof(defaults)/sizeof(defaults[0]));i++) NpProcessHideAdd(defaults[i]);
    //
    // 查看者默认名单：自家调试器发起的枚举不过滤（否则附加窗口看不见目标）。
    //
    const wchar_t* watchDefaults[]={L"x64dbg.exe",L"x32dbg.exe"};
    for(int i=0;i<(int)(sizeof(watchDefaults)/sizeof(watchDefaults[0]));i++) NpProcessWatchAdd(watchDefaults[i]);
    return STATUS_SUCCESS;
}
VOID NpProcessHideTeardown(VOID){
    NpProcessHideSetEnabled(FALSE);
    NpProcessHideClearAll();
    KIRQL irql; KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_VIEWER_MAX;i++) if(g_ViewerNames[i].Buffer){ ExFreePoolWithTag(g_ViewerNames[i].Buffer,'hVwN'); RtlZeroMemory(&g_ViewerNames[i],sizeof(UNICODE_STRING)); }
    KeReleaseSpinLock(&g_HideLock,irql);
}
NTSTATUS NpProcessHideSetEnabled(BOOLEAN Enable){
    if(Enable){
        if(g_HideEnabled) return STATUS_SUCCESS;

        //
        // LSTAR 模式：QSI 走动态拦截（不再依赖 NpHook 克隆重定位，
        // 规避目标机上 QSI 克隆失败导致 prochide 失效）。
        //
        if (NpLstarIsEnabled())
        {
            NTSTATUS st = NpSyscallSetIntercept("NtQuerySystemInformation", TRUE);
            if (NT_SUCCESS(st))
            {
                st = NpLstarRefresh();
            }
            if (!NT_SUCCESS(st))
            {
                return st;
            }
            PVOID addr = NpSyscallResolveRoutine("NtQuerySystemInformation", nullptr);
            if (addr == nullptr)
            {
                NpSyscallSetIntercept("NtQuerySystemInformation", FALSE);
                NpLstarRefresh();
                return STATUS_NOT_FOUND;
            }
            g_OrigQSI = (ULONG_PTR)addr;
            g_HideEnabled = TRUE;
            NpHvLogPrint("[prochide] enabled via LSTAR (QSI intercept)\n");
            return STATUS_SUCCESS;
        }

        PVOID addr=nullptr; UNICODE_STRING n; RtlInitUnicodeString(&n,L"NtQuerySystemInformation");
        addr=MmGetSystemRoutineAddress(&n);
        if(!addr){ RtlInitUnicodeString(&n,L"ZwQuerySystemInformation"); addr=MmGetSystemRoutineAddress(&n); }
        if(!addr) return STATUS_NOT_FOUND;
        g_OrigQSI=(ULONG_PTR)addr;
        NTSTATUS st=NpHookInstallHook((ULONG_PTR)addr, NpProcessHideHook, &g_HookQSI);
        if(!NT_SUCCESS(st)){ g_OrigQSI=0; return st; }
        g_HideEnabled=TRUE; NpHvLogPrint("[prochide] enabled hook %p\n",addr); return STATUS_SUCCESS;
    } else {
        if (NpLstarIsEnabled())
        {
            NpSyscallSetIntercept("NtQuerySystemInformation", FALSE);
            NpLstarRefresh();
            g_OrigQSI = 0;
            g_HideEnabled = FALSE;
            NpHvLogPrint("[prochide] disabled\n");
            return STATUS_SUCCESS;
        }
        if(g_HookQSI){ NpHookUninstallHook(g_HookQSI,FALSE); g_HookQSI=nullptr; }
        g_OrigQSI=0; g_HideEnabled=FALSE; NpHvLogPrint("[prochide] disabled\n"); return STATUS_SUCCESS;
    }
}
BOOLEAN NpProcessHideIsEnabled(VOID){ return g_HideEnabled; }
BOOLEAN NpProcessHideIsStealthActive(VOID){
    //
    // 复位线程用：过滤 hook 启用期间，命中后页面会进入 C 态（干净可执行）
    // 直到下次 vmmcall 复位。此窗口内同核其他线程的调用会绕过过滤——
    // 所以活跃期间把复位周期从 5ms 收紧到 1ms，压缩暴露面。
    //
    return g_HideEnabled;
}
NTSTATUS NpProcessHideAdd(const wchar_t* Name){
    if(!Name||!*Name) return STATUS_INVALID_PARAMETER;
    size_t len=wcslen(Name)*sizeof(wchar_t);
    PWCH copy=(PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED,len+sizeof(wchar_t),'dHpN');
    if(!copy) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy,Name,len); copy[wcslen(Name)]=0;
    UNICODE_STRING us; RtlInitUnicodeString(&us,copy);
    KIRQL irql; NTSTATUS st=STATUS_NO_MEMORY;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++) if(g_HiddenNames[i].Buffer==0){ g_HiddenNames[i]=us; st=STATUS_SUCCESS; break; }
    KeReleaseSpinLock(&g_HideLock,irql);
    if(!NT_SUCCESS(st)) ExFreePoolWithTag(copy,'dHpN');
    return st;
}
NTSTATUS NpProcessHideRemove(const wchar_t* Name){
    if(!Name) return STATUS_INVALID_PARAMETER;
    UNICODE_STRING target; RtlInitUnicodeString(&target,Name);
    KIRQL irql; NTSTATUS st=STATUS_NOT_FOUND;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++) if(g_HiddenNames[i].Buffer && RtlCompareUnicodeString(&g_HiddenNames[i],&target,TRUE)==0){ ExFreePoolWithTag(g_HiddenNames[i].Buffer,'dHpN'); RtlZeroMemory(&g_HiddenNames[i],sizeof(UNICODE_STRING)); st=STATUS_SUCCESS; break; }
    KeReleaseSpinLock(&g_HideLock,irql);
    return st;
}
NTSTATUS NpProcessHideAddPid(ULONG ProcessId){
    if(ProcessId == 0 || ProcessId == 4) return STATUS_INVALID_PARAMETER;
    HANDLE pid = ULongToHandle(ProcessId);
    KIRQL irql; NTSTATUS st=STATUS_NO_MEMORY;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++){
        if(g_HiddenPids[i] == pid){ st=STATUS_SUCCESS; break; }
        if(g_HiddenPids[i] == nullptr){ g_HiddenPids[i]=pid; st=STATUS_SUCCESS; break; }
    }
    KeReleaseSpinLock(&g_HideLock,irql);
    return st;
}
NTSTATUS NpProcessHideRemovePid(ULONG ProcessId){
    if(ProcessId == 0) return STATUS_INVALID_PARAMETER;
    HANDLE pid = ULongToHandle(ProcessId);
    KIRQL irql; NTSTATUS st=STATUS_NOT_FOUND;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++){
        if(g_HiddenPids[i] == pid){ g_HiddenPids[i]=nullptr; st=STATUS_SUCCESS; break; }
    }
    KeReleaseSpinLock(&g_HideLock,irql);
    return st;
}
VOID NpProcessHideClearAll(VOID){
    KIRQL irql; KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++) if(g_HiddenNames[i].Buffer){ ExFreePoolWithTag(g_HiddenNames[i].Buffer,'dHpN'); RtlZeroMemory(&g_HiddenNames[i],sizeof(UNICODE_STRING)); }
    RtlZeroMemory(g_HiddenPids,sizeof(g_HiddenPids));
    KeReleaseSpinLock(&g_HideLock,irql);
}
ULONG NpProcessHideGetCount(VOID){
    ULONG c=0; KIRQL irql; KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX;i++) if(g_HiddenNames[i].Buffer) c++;
    KeReleaseSpinLock(&g_HideLock,irql); return c;
}
ULONG NpProcessHideCopyNames(wchar_t* Names, ULONG MaxEntries){
    //
    // 全程持锁拷贝到 METHOD_BUFFERED 系统缓冲（内核 VA，无用户指针）。
    // 单名最长 63 字符 + NUL；超出 MaxEntries 的条目丢弃（调用方以返回值
    // 为准填充 Count，保证 Count 与实际拷贝数一致）。
    //
    ULONG c=0; KIRQL irql;
    if(!Names || MaxEntries==0) return 0;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_PROCESS_HIDE_MAX && c<MaxEntries;i++){
        UNICODE_STRING* src=&g_HiddenNames[i];
        if(!src->Buffer || !src->Length) continue;
        SIZE_T chars = src->Length / sizeof(wchar_t);
        if(chars > 63) chars = 63;
        RtlCopyMemory(Names + c*64, src->Buffer, chars*sizeof(wchar_t));
        Names[c*64 + chars] = 0;
        c++;
    }
    KeReleaseSpinLock(&g_HideLock,irql);
    return c;
}

// ============================ 查看者豁免名单 ============================

NTSTATUS NpProcessWatchAdd(const wchar_t* Name){
    if(!Name||!*Name) return STATUS_INVALID_PARAMETER;
    size_t len=wcslen(Name)*sizeof(wchar_t);
    PWCH copy=(PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED,len+sizeof(wchar_t),'hVwN');
    if(!copy) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy,Name,len); copy[wcslen(Name)]=0;
    UNICODE_STRING us; RtlInitUnicodeString(&us,copy);
    KIRQL irql; NTSTATUS st=STATUS_NO_MEMORY;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_VIEWER_MAX;i++) if(g_ViewerNames[i].Buffer==0){ g_ViewerNames[i]=us; st=STATUS_SUCCESS; break; }
    KeReleaseSpinLock(&g_HideLock,irql);
    if(!NT_SUCCESS(st)) ExFreePoolWithTag(copy,'hVwN');
    return st;
}
NTSTATUS NpProcessWatchRemove(const wchar_t* Name){
    if(!Name) return STATUS_INVALID_PARAMETER;
    UNICODE_STRING target; RtlInitUnicodeString(&target,Name);
    KIRQL irql; NTSTATUS st=STATUS_NOT_FOUND;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_VIEWER_MAX;i++) if(g_ViewerNames[i].Buffer && RtlCompareUnicodeString(&g_ViewerNames[i],&target,TRUE)==0){ ExFreePoolWithTag(g_ViewerNames[i].Buffer,'hVwN'); RtlZeroMemory(&g_ViewerNames[i],sizeof(UNICODE_STRING)); st=STATUS_SUCCESS; break; }
    KeReleaseSpinLock(&g_HideLock,irql);
    return st;
}
ULONG NpProcessWatchCopyNames(wchar_t* Names, ULONG MaxEntries){
    ULONG c=0; KIRQL irql;
    if(!Names || MaxEntries==0) return 0;
    KeAcquireSpinLock(&g_HideLock,&irql);
    for(int i=0;i<NP_VIEWER_MAX && c<MaxEntries;i++){
        UNICODE_STRING* src=&g_ViewerNames[i];
        if(!src->Buffer || !src->Length) continue;
        SIZE_T chars = src->Length / sizeof(wchar_t);
        if(chars > 63) chars = 63;
        RtlCopyMemory(Names + c*64, src->Buffer, chars*sizeof(wchar_t));
        Names[c*64 + chars] = 0;
        c++;
    }
    KeReleaseSpinLock(&g_HideLock,irql);
    return c;
}
