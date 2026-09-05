/*!
    @file       NpDataPatch.cpp

    @brief      P5 数据补丁实现（读点虚拟化 + 纯数据页影子备选）。
 */
#define POOL_NX_OPTIN 1
#include "NpDataPatch.h"
#include "NpHook.h"
#include "NpBreakPoint.h"
#include "NpVHook.h"
#include "NpMemAccess.h"
#include "NpLog.h"

#define NP_DP_TAG 'pDpN'
#define X86_RFLAGS_TF 0x100

typedef struct _NP_DATA_PATCH {
    LIST_ENTRY Link;
    ULONG Id;
    BOOLEAN Active;
    ULONG Flags;                // NPHV_DATA_PATCH_*
    ULONG TargetPid;
    ULONG_PTR Va;
    ULONG_PTR PageVa;
    ULONG_PTR PageGpa;
    ULONG Offset;
    ULONG Length;
    UCHAR Bytes[NPHV_DATA_PATCH_MAX_LEN];

    // PAGE_SHADOW 专属
    PVOID ShadowPage;
    ULONG_PTR ShadowPA;
    PMDL Mdl;
} NP_DATA_PATCH, *PNP_DATA_PATCH;

typedef struct _NP_DP_CPU_STATE {
    BOOLEAN InStep;
    ULONG_PTR PageGpa;
    PNP_DATA_PATCH Patch;
} NP_DP_CPU_STATE;

static LIST_ENTRY g_PatchList;
static KSPIN_LOCK g_PatchLock;
static ULONG g_NextId = 1;
static NP_DP_CPU_STATE *g_CpuState = nullptr;
static ULONG g_CpuCount = 0;

static PNP_DATA_PATCH FindById(ULONG Id)
{
    for (PLIST_ENTRY e = g_PatchList.Flink; e != &g_PatchList; e = e->Flink)
    {
        PNP_DATA_PATCH p = CONTAINING_RECORD(e, NP_DATA_PATCH, Link);
        if (p->Active && p->Id == Id) return p;
    }
    return nullptr;
}

static PNP_DATA_PATCH FindByPage(ULONG_PTR PageGpa)
{
    for (PLIST_ENTRY e = g_PatchList.Flink; e != &g_PatchList; e = e->Flink)
    {
        PNP_DATA_PATCH p = CONTAINING_RECORD(e, NP_DATA_PATCH, Link);
        if (p->Active && (p->Flags & NPHV_DATA_PATCH_PAGE_SHADOW) &&
            p->PageGpa == (PageGpa & ~(ULONG_PTR)0xFFF))
        {
            return p;
        }
    }
    return nullptr;
}

BOOLEAN NpDataPatchIsPageOccupied(ULONG_PTR PageGpa)
{
    KIRQL irql;
    BOOLEAN hit = FALSE;
    PageGpa &= ~(ULONG_PTR)0xFFF;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    hit = (FindByPage(PageGpa) != nullptr);
    KeReleaseSpinLock(&g_PatchLock, irql);
    return hit;
}

NTSTATUS NpDataPatchInitialize(void)
{
    InitializeListHead(&g_PatchList);
    KeInitializeSpinLock(&g_PatchLock);
    g_NextId = 1;
    g_CpuCount = NpHvGetProcessorCount();
    if (g_CpuCount == 0) g_CpuCount = 1;
    g_CpuState = (NP_DP_CPU_STATE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(NP_DP_CPU_STATE) * g_CpuCount, NP_DP_TAG);
    if (!g_CpuState) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_CpuState, sizeof(NP_DP_CPU_STATE) * g_CpuCount);

    NpHvRegisterVmExitHandler(VMEXIT_NPF, NpDataPatchHandleNpf);
    NpHvRegisterVmExitHandler(VMEXIT_EXCEPTION_DB, NpDataPatchHandleDebug);
    NpHvRegisterVmExitHandler(VMEXIT_VMMCALL, NpDataPatchHandleVmmcall);
    return STATUS_SUCCESS;
}

void NpDataPatchTeardown(void)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    while (!IsListEmpty(&g_PatchList))
    {
        PLIST_ENTRY e = RemoveHeadList(&g_PatchList);
        PNP_DATA_PATCH p = CONTAINING_RECORD(e, NP_DATA_PATCH, Link);
        if (p->Mdl != nullptr)
        {
            MmUnlockPages(p->Mdl);
            IoFreeMdl(p->Mdl);
        }
        if (p->ShadowPage != nullptr) ExFreePoolWithTag(p->ShadowPage, NP_DP_TAG);
        ExFreePoolWithTag(p, NP_DP_TAG);
    }
    KeReleaseSpinLock(&g_PatchLock, irql);
    if (g_CpuState != nullptr)
    {
        ExFreePoolWithTag(g_CpuState, NP_DP_TAG);
        g_CpuState = nullptr;
    }
}

NTSTATUS NpDataPatchInstall(ULONG TargetPid, ULONG_PTR Va,
                            const UCHAR *Bytes, ULONG Length,
                            ULONG Flags, PULONG OutId)
{
    if (Va == 0 || Bytes == nullptr || Length == 0 ||
        Length > NPHV_DATA_PATCH_MAX_LEN ||
        ((Va & 0xFFF) + Length) > PAGE_SIZE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PNP_DATA_PATCH p = (PNP_DATA_PATCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*p), NP_DP_TAG);
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(p, sizeof(*p));
    p->Id = (ULONG)InterlockedIncrement((volatile LONG *)&g_NextId);
    p->Flags = Flags;
    p->TargetPid = TargetPid;
    p->Va = Va;
    p->PageVa = Va & ~(ULONG_PTR)0xFFF;
    p->Offset = (ULONG)(Va & 0xFFF);
    p->Length = Length;
    RtlCopyMemory(p->Bytes, Bytes, Length);
    p->Active = TRUE;

    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = nullptr;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    if (Flags & NPHV_DATA_PATCH_PAGE_SHADOW)
    {
        //
        // 纯数据页影子：pin 目标物理页 + 建影子副本，随后逐核
        // 设置 not-present（访问计费）。
        //
        if (TargetPid != 0)
        {
            if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(TargetPid),
                                                       &process)) ||
                process == nullptr)
            {
                status = STATUS_NOT_FOUND;
                goto Exit;
            }
            KeStackAttachProcess(process, &apcState);
            attached = TRUE;
        }

        p->ShadowPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, NP_DP_TAG);
        if (!p->ShadowPage)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        __try
        {
            ProbeForRead((PVOID)p->PageVa, PAGE_SIZE, 1);
            if (attached)
            {
                p->Mdl = IoAllocateMdl((PVOID)p->PageVa, PAGE_SIZE, FALSE, FALSE, nullptr);
                if (p->Mdl != nullptr)
                    MmProbeAndLockPages(p->Mdl, KernelMode, IoReadAccess);
            }
            RtlCopyMemory(p->ShadowPage, (PVOID)p->PageVa, PAGE_SIZE);
            p->PageGpa = MmGetPhysicalAddress((PVOID)p->PageVa).QuadPart;
            p->ShadowPA = MmGetPhysicalAddress(p->ShadowPage).QuadPart;
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = STATUS_NOT_FOUND;
        }

        if (attached)
        {
            KeUnstackDetachProcess(&apcState);
            attached = FALSE;
        }
        if (!NT_SUCCESS(status)) goto Exit;

        RtlCopyMemory((PUCHAR)p->ShadowPage + p->Offset, Bytes, Length);

        //
        // 同页互斥：先查其它模块（各自持锁），再持本模块锁只查自己。
        // 不能在持有 g_PatchLock 时反向查其它模块锁（锁序反转死锁）。
        //
        if (NpBreakPointIsPageOccupied(p->PageGpa) ||
            NpHookIsPageHooked(p->PageGpa) ||
            NpVHookIsPageOccupied(p->PageGpa))
        {
            status = STATUS_ALREADY_REGISTERED;
            goto Exit;
        }
        KIRQL irql;
        KeAcquireSpinLock(&g_PatchLock, &irql);
        if (FindByPage(p->PageGpa) != nullptr)
        {
            KeReleaseSpinLock(&g_PatchLock, irql);
            status = STATUS_ALREADY_REGISTERED;
            goto Exit;
        }
        InsertTailList(&g_PatchList, &p->Link);
        KeReleaseSpinLock(&g_PatchLock, irql);

        // 逐核武装 not-present。
        for (ULONG cpu = 0; cpu < g_CpuCount; cpu++)
        {
            PVIRTUAL_PROCESSOR_DATA vp = nullptr;
            if (!NT_SUCCESS(NpHvGetProcessorData(cpu, &vp)) || vp == nullptr)
                continue;
            PNPT_ENTRY leaf = nullptr;
            if (NpHookGetLeafEntry(vp->NptRoot, p->PageGpa, &leaf))
            {
                NPT_ENTRY e = *leaf;
                e.Fields.Present = 0;
                InterlockedExchange64((volatile LONG64 *)leaf, e.AsUInt64);
                vp->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;
            }
        }
    }
    else
    {
        // 读点虚拟化：只登记（RVM 叠加）。
        KIRQL irql;
        KeAcquireSpinLock(&g_PatchLock, &irql);
        InsertTailList(&g_PatchList, &p->Link);
        KeReleaseSpinLock(&g_PatchLock, irql);
    }

    if (OutId != nullptr) *OutId = p->Id;
    NpHvLogPrint("[datapatch] install id=%lu pid=%lu va=0x%p len=%lu flags=0x%x\n",
                 p->Id, TargetPid, (PVOID)Va, Length, Flags);
    return STATUS_SUCCESS;

Exit:
    if (attached) KeUnstackDetachProcess(&apcState);
    if (p->Mdl != nullptr)
    {
        MmUnlockPages(p->Mdl);
        IoFreeMdl(p->Mdl);
    }
    if (p->ShadowPage != nullptr) ExFreePoolWithTag(p->ShadowPage, NP_DP_TAG);
    ExFreePoolWithTag(p, NP_DP_TAG);
    return status;
}

NTSTATUS NpDataPatchRemove(ULONG Id)
{
    KIRQL irql;
    PNP_DATA_PATCH p = nullptr;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    p = FindById(Id);
    if (p == nullptr)
    {
        KeReleaseSpinLock(&g_PatchLock, irql);
        return STATUS_NOT_FOUND;
    }
    p->Active = FALSE;
    RemoveEntryList(&p->Link);
    KeReleaseSpinLock(&g_PatchLock, irql);

    if (p->Flags & NPHV_DATA_PATCH_PAGE_SHADOW)
    {
        // 恢复恒等映射。
        for (ULONG cpu = 0; cpu < g_CpuCount; cpu++)
        {
            PVIRTUAL_PROCESSOR_DATA vp = nullptr;
            if (!NT_SUCCESS(NpHvGetProcessorData(cpu, &vp)) || vp == nullptr)
                continue;
            NpHookSetLeaf(vp, p->PageGpa, p->PageGpa, FALSE, TRUE);
        }
    }

    if (p->Mdl != nullptr)
    {
        MmUnlockPages(p->Mdl);
        IoFreeMdl(p->Mdl);
    }
    if (p->ShadowPage != nullptr) ExFreePoolWithTag(p->ShadowPage, NP_DP_TAG);
    ExFreePoolWithTag(p, NP_DP_TAG);
    return STATUS_SUCCESS;
}

VOID NpDataPatchList(PNPHV_DATA_PATCH_LIST_RESPONSE Resp)
{
    if (Resp == nullptr) return;
    RtlZeroMemory(Resp, sizeof(*Resp));
    KIRQL irql;
    ULONG i = 0;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    for (PLIST_ENTRY e = g_PatchList.Flink;
         e != &g_PatchList && i < NPHV_DATA_PATCH_MAX_ENTRIES_CTL;
         e = e->Flink)
    {
        PNP_DATA_PATCH p = CONTAINING_RECORD(e, NP_DATA_PATCH, Link);
        if (!p->Active) continue;
        Resp->Entries[i].PatchId = p->Id;
        Resp->Entries[i].TargetPid = p->TargetPid;
        Resp->Entries[i].Va = (uint64_t)p->Va;
        Resp->Entries[i].Flags = p->Flags;
        Resp->Entries[i].Length = p->Length;
        i++;
    }
    Resp->Count = i;
    Resp->Status = STATUS_SUCCESS;
    KeReleaseSpinLock(&g_PatchLock, irql);
}

BOOLEAN NpDataPatchApplyToBuffer(ULONG TargetPid, ULONG_PTR Va,
                                 PVOID Buffer, ULONG Size)
{
    if (Buffer == nullptr || Size == 0) return FALSE;
    KIRQL irql;
    BOOLEAN applied = FALSE;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    for (PLIST_ENTRY e = g_PatchList.Flink; e != &g_PatchList; e = e->Flink)
    {
        PNP_DATA_PATCH p = CONTAINING_RECORD(e, NP_DATA_PATCH, Link);
        if (!p->Active || p->TargetPid != TargetPid) continue;
        if (p->Flags & NPHV_DATA_PATCH_PAGE_SHADOW) continue;  // 影子路径自管

        ULONG_PTR pStart = p->Va;
        ULONG_PTR pEnd = p->Va + p->Length;
        ULONG_PTR rStart = Va;
        ULONG_PTR rEnd = Va + Size;
        if (pStart < rEnd && rStart < pEnd)
        {
            ULONG_PTR b0 = (pStart > rStart) ? pStart : rStart;
            ULONG_PTR b1 = (pEnd < rEnd) ? pEnd : rEnd;
            for (ULONG_PTR x = b0; x < b1; x++)
            {
                ((PUCHAR)Buffer)[x - rStart] = p->Bytes[x - pStart];
            }
            applied = TRUE;
        }
    }
    KeReleaseSpinLock(&g_PatchLock, irql);
    return applied;
}

//
// ============================ 纯数据页影子 VMEXIT ============================
//

static void SetShadowArmed(PVIRTUAL_PROCESSOR_DATA VpData, PNP_DATA_PATCH p)
{
    PNPT_ENTRY leaf = nullptr;
    if (!NpHookGetLeafEntry(VpData->NptRoot, p->PageGpa, &leaf)) return;
    NPT_ENTRY e = *leaf;
    e.Fields.Present = 0;
    InterlockedExchange64((volatile LONG64 *)leaf, e.AsUInt64);
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;
}

BOOLEAN NpDataPatchHandleNpf(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)
{
    ULONG_PTR faultGpa = VpData->GuestVmcb.ControlArea.ExitInfo2;
    ULONG errorCode = (ULONG)(VpData->GuestVmcb.ControlArea.ExitInfo1 & MAXUINT32);
    UNREFERENCED_PARAMETER(Ctx);

    if (g_CpuState == nullptr || VpData->CpuIndex >= g_CpuCount) return FALSE;
    PNP_DATA_PATCH p = nullptr;
    KIRQL irql;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    p = FindByPage(faultGpa);
    KeReleaseSpinLock(&g_PatchLock, irql);
    if (p == nullptr) return FALSE;

    if ((errorCode & NPF_ERROR_PRESENT) != 0)
    {
        // 理论上武装态为 not-present；若处于放行态又触发，直接恢复。
        SetShadowArmed(VpData, p);
        return TRUE;
    }

    // 翻转 leaf 到影子页 + TF 单步一条指令。
    PNPT_ENTRY leaf = nullptr;
    if (!NpHookGetLeafEntry(VpData->NptRoot, p->PageGpa, &leaf)) return TRUE;
    NPT_ENTRY e;
    e.AsUInt64 = 0;
    e.Fields.Present = 1;
    e.Fields.Write = 1;
    e.Fields.User = 1;
    e.Fields.Accessed = 1;
    e.Fields.Dirty = 1;
    e.Fields.PageFrameNumber = p->ShadowPA >> 12;
    InterlockedExchange64((volatile LONG64 *)leaf, e.AsUInt64);
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;

    VpData->GuestVmcb.StateSaveArea.Rflags |= X86_RFLAGS_TF;
    g_CpuState[VpData->CpuIndex].InStep = TRUE;
    g_CpuState[VpData->CpuIndex].PageGpa = p->PageGpa;
    g_CpuState[VpData->CpuIndex].Patch = p;
    return TRUE;
}

BOOLEAN NpDataPatchHandleDebug(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    if (g_CpuState == nullptr || VpData->CpuIndex >= g_CpuCount ||
        !g_CpuState[VpData->CpuIndex].InStep)
    {
        return FALSE;
    }
    NP_DP_CPU_STATE *cs = &g_CpuState[VpData->CpuIndex];
    PNP_DATA_PATCH p = cs->Patch;
    ULONG_PTR pageGpa = cs->PageGpa;
    cs->InStep = FALSE;
    cs->Patch = nullptr;
    cs->PageGpa = 0;
    VpData->GuestVmcb.StateSaveArea.Rflags &= ~X86_RFLAGS_TF;
    if (p != nullptr && p->Active)
    {
        SetShadowArmed(VpData, p);
    }
    else
    {
        if (pageGpa != 0)
            NpHookSetLeaf(VpData, pageGpa, pageGpa, FALSE, TRUE);
    }
    return TRUE;
}

BOOLEAN NpDataPatchHandleVmmcall(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)
{
    if ((ULONG)(Ctx->VpRegs->Rax & 0xFFFFFFFF) != VMMCALL_RESET_SHADOWS)
    {
        return FALSE;
    }
    // 复位线程：把全部影子页重新武装为 not-present（跳过单步中）。
    KIRQL irql;
    KeAcquireSpinLock(&g_PatchLock, &irql);
    for (PLIST_ENTRY e = g_PatchList.Flink; e != &g_PatchList; e = e->Flink)
    {
        PNP_DATA_PATCH p = CONTAINING_RECORD(e, NP_DATA_PATCH, Link);
        if (!p->Active || !(p->Flags & NPHV_DATA_PATCH_PAGE_SHADOW)) continue;
        if (g_CpuState != nullptr && VpData->CpuIndex < g_CpuCount &&
            g_CpuState[VpData->CpuIndex].InStep &&
            g_CpuState[VpData->CpuIndex].PageGpa == p->PageGpa)
        {
            continue;   // 单步窗口内不打断
        }
        SetShadowArmed(VpData, p);
    }
    KeReleaseSpinLock(&g_PatchLock, irql);
    return FALSE;       // 让后续 handler 继续（Hook/断点复位）
}
