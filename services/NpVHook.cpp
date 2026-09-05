/*!
    @file       NpVHook.cpp

    @brief      P4 虚拟内联钩子实现。

    @details    Cave 布局：
                    [PatchCode][NpReloc 重定位后的剩余块][mov rax,imm64; jmp rax]
                执行流：
                    目标页 NX=1 → 入口取指 #NPF（且当前进程 == 目标）
                    → 叶子放行（原物理页）+ guest RIP = CaveVA
                    → Cave 执行补丁 + 剩余块 → 跳回 原地址+覆盖长度
                    → 复位线程周期重武装 NX（暴露窗口仅限本次调用期间）
 */
#define POOL_NX_OPTIN 1
#include "NpVHook.h"
#include "NpHv.h"
#include "NpHook.h"
#include "NpBreakPoint.h"
#include "NpDataPatch.h"
#include "NpReloc.h"
#include "NpDisasm.hpp"
#include "NpLog.h"

#define NP_VHOOK_TAG 'HvVc'

typedef struct _VHOOK_ENTRY {
    LIST_ENTRY Link;
    ULONG Id;
    BOOLEAN Active;
    ULONG TargetPid;
    ULONG_PTR TargetVa;
    ULONG_PTR PageGpa;
    ULONG PageOffset;
    ULONG PrologLen;
    ULONG_PTR CaveVa;
    PVOID CaveAlloc;            // 释放用原始指针（用户：分配基址；内核：池）
    BOOLEAN UserCave;
    ULONG CaveSize;
    PMDL Mdl;                   // 用户目标页 pin
} VHOOK_ENTRY, *PVHOOK_ENTRY;

static LIST_ENTRY g_VHookList;
static KSPIN_LOCK g_Lock;
static ULONG g_NextId = 1;
static LIST_ENTRY g_RetiredList;

static PVHOOK_ENTRY FindById(ULONG Id)
{
    for (PLIST_ENTRY e = g_VHookList.Flink; e != &g_VHookList; e = e->Flink)
    {
        PVHOOK_ENTRY v = CONTAINING_RECORD(e, VHOOK_ENTRY, Link);
        if (v->Active && v->Id == Id) return v;
    }
    return nullptr;
}

static PVHOOK_ENTRY FindByPage(ULONG_PTR PageGpa)
{
    for (PLIST_ENTRY e = g_VHookList.Flink; e != &g_VHookList; e = e->Flink)
    {
        PVHOOK_ENTRY v = CONTAINING_RECORD(e, VHOOK_ENTRY, Link);
        if (v->Active && v->PageGpa == (PageGpa & ~(ULONG_PTR)0xFFF))
            return v;
    }
    return nullptr;
}

NTSTATUS NpVHookInitialize(void)
{
    InitializeListHead(&g_VHookList);
    InitializeListHead(&g_RetiredList);
    KeInitializeSpinLock(&g_Lock);
    g_NextId = 1;
    NpHvRegisterVmExitHandler(VMEXIT_NPF, NpVHookHandleNpf);
    NpHvRegisterVmExitHandler(VMEXIT_VMMCALL, NpVHookHandleVmmcall);
    return STATUS_SUCCESS;
}

static void FreeEntry(PVHOOK_ENTRY v)
{
    if (v->Mdl != nullptr)
    {
        MmUnlockPages(v->Mdl);
        IoFreeMdl(v->Mdl);
    }
    if (v->UserCave)
    {
        if (v->CaveAlloc != nullptr)
        {
            PEPROCESS proc = nullptr;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    ULongToHandle(v->TargetPid), &proc)) && proc != nullptr)
            {
                KAPC_STATE apc;
                KeStackAttachProcess(proc, &apc);
                PVOID base = v->CaveAlloc;
                SIZE_T size = 0;
                ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size,
                                    MEM_RELEASE);
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
            }
        }
    }
    else if (v->CaveAlloc != nullptr)
    {
        ExFreePoolWithTag(v->CaveAlloc, NP_VHOOK_TAG);
    }
    ExFreePoolWithTag(v, NP_VHOOK_TAG);
}

void NpVHookTeardown(void)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    while (!IsListEmpty(&g_VHookList))
    {
        PLIST_ENTRY e = RemoveHeadList(&g_VHookList);
        PVHOOK_ENTRY v = CONTAINING_RECORD(e, VHOOK_ENTRY, Link);
        KeReleaseSpinLock(&g_Lock, irql);
        FreeEntry(v);
        KeAcquireSpinLock(&g_Lock, &irql);
    }
    while (!IsListEmpty(&g_RetiredList))
    {
        PLIST_ENTRY e = RemoveHeadList(&g_RetiredList);
        PVHOOK_ENTRY v = CONTAINING_RECORD(e, VHOOK_ENTRY, Link);
        KeReleaseSpinLock(&g_Lock, irql);
        FreeEntry(v);
        KeAcquireSpinLock(&g_Lock, &irql);
    }
    KeReleaseSpinLock(&g_Lock, irql);
}

//
// ============================ Cave 构建 ============================
//

static NTSTATUS BuildCave(PVOID SrcBlock, ULONG_PTR OrigPageVa,
                          ULONG HookOff, ULONG PrologLen,
                          const UCHAR *PatchCode, ULONG PatchLen,
                          PUCHAR OutBuf, ULONG OutCap, PULONG OutLen)
{
    using namespace NptHook;
    PUCHAR p = OutBuf;
    ULONG remaining = OutCap;

    // 1. 补丁逻辑。
    if (PatchLen > remaining) return STATUS_BUFFER_OVERFLOW;
    RtlCopyMemory(p, PatchCode, PatchLen);
    p += PatchLen;
    remaining -= PatchLen;

    // 2. 剩余块（HookOff+PrologLen 起到块尾）重定位为位置无关代码。
    // 4096 * 8B = 32KB：不能放内核栈（_chkstk 探测会越过线程栈底 → 0x50）。
    NP_RELOC_MAP* map = static_cast<NP_RELOC_MAP*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        sizeof(NP_RELOC_MAP) * NP_RELOC_MAX_ENTRIES,
                        NP_VHOOK_TAG));
    if (map == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    NP_RELOC_RESULT res;
    RtlZeroMemory(&res, sizeof(res));
    res.Map = map;
    res.MapCapacity = NP_RELOC_MAX_ENTRIES;
    NP_RELOC_RANGE range;
    range.Beg = HookOff + PrologLen;
    range.End = NP_RELOC_BLOCK_SIZE;
    bool ok = NpRelocRelocateBlock(
        (const uint8_t *)SrcBlock, OrigPageVa, HookOff,
        &range, 1, p, remaining, &res);
    if (!ok)
    {
        ExFreePoolWithTag(map, NP_VHOOK_TAG);
        return STATUS_NOT_SUPPORTED;
    }
    p += res.OutLen;
    remaining -= res.OutLen;

    // 3. 跳回桩：mov rax, imm64; jmp rax
    if (remaining < 12)
    {
        ExFreePoolWithTag(map, NP_VHOOK_TAG);
        return STATUS_BUFFER_OVERFLOW;
    }
    p[0] = 0x48; p[1] = 0xB8;
    *(ULONG64 *)(p + 2) = (ULONG64)(OrigPageVa + HookOff + PrologLen);
    p[10] = 0xFF; p[11] = 0xE0;
    p += 12;

    *OutLen = (ULONG)(p - OutBuf);
    ExFreePoolWithTag(map, NP_VHOOK_TAG);
    return STATUS_SUCCESS;
}

static NTSTATUS AllocateCave(ULONG TargetPid, PUCHAR CaveBuf, ULONG CaveLen,
                             PULONG_PTR OutCaveVa, PVOID *OutAlloc,
                             PBOOLEAN OutUser)
{
    if (TargetPid == 0)
    {
        PVOID pool = ExAllocatePool2(POOL_FLAG_NON_PAGED |
                                     POOL_FLAG_NON_PAGED_EXECUTE,
                                     CaveLen, NP_VHOOK_TAG);
        if (!pool) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(pool, CaveBuf, CaveLen);
        *OutCaveVa = (ULONG_PTR)pool;
        *OutAlloc = pool;
        *OutUser = FALSE;
        return STATUS_SUCCESS;
    }

    PEPROCESS proc = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(TargetPid),
                                               &proc)) || proc == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);
    PVOID base = nullptr;
    SIZE_T size = (SIZE_T)((CaveLen + 0xFFF) & ~(ULONG_PTR)0xFFF);
    NTSTATUS st = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &size,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(st) && base != nullptr)
    {
        __try
        {
            RtlCopyMemory(base, CaveBuf, CaveLen);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            st = STATUS_UNSUCCESSFUL;
        }
    }
    if (!NT_SUCCESS(st))
    {
        if (base != nullptr)
        {
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
        }
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        return st;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    *OutCaveVa = (ULONG_PTR)base;
    *OutAlloc = base;
    *OutUser = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS NpVHookInstall(ULONG ProcessId, ULONG_PTR HookPointVa,
                        PVOID PatchLogic, ULONG PatchLogicLen,
                        ULONG_PTR *OutCaveVa, ULONG *OutId)
{
    if (OutCaveVa) *OutCaveVa = 0;
    if (OutId) *OutId = 0;
    if (HookPointVa == 0 || PatchLogic == nullptr ||
        PatchLogicLen == 0 || PatchLogicLen > NPHV_VHOOK_MAX_LEN)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (ProcessId == 0 && HookPointVa < 0xFFFF800000000000ULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 目标页定位 + 8KB 源块拷贝（用户页 attach + MDL pin）。
    PEPROCESS process = nullptr;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    PMDL mdl = nullptr;
    ULONG_PTR pageVa = HookPointVa & ~(ULONG_PTR)0xFFF;
    ULONG_PTR pageGpa = 0;
    PVOID src = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG prologLen = 0;
    PVOID caveBuf = nullptr;
    ULONG caveLen = 0;
    ULONG_PTR caveVa = 0;
    PVOID caveAlloc = nullptr;
    BOOLEAN userCave = FALSE;
    PVHOOK_ENTRY v = nullptr;

    if (ProcessId != 0)
    {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(ProcessId),
                                                   &process)) ||
            process == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        KeStackAttachProcess(process, &apcState);
        attached = TRUE;
    }

    src = ExAllocatePool2(POOL_FLAG_NON_PAGED, NP_RELOC_BLOCK_SIZE, NP_VHOOK_TAG);
    if (!src)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(src, NP_RELOC_BLOCK_SIZE);

    __try
    {
        ProbeForRead((PVOID)pageVa, PAGE_SIZE, 1);
        RtlCopyMemory(src, (PVOID)pageVa, PAGE_SIZE);
        if (attached)
        {
            mdl = IoAllocateMdl((PVOID)pageVa, PAGE_SIZE, FALSE, FALSE, nullptr);
            if (mdl != nullptr)
                MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        }
        pageGpa = MmGetPhysicalAddress((PVOID)pageVa).QuadPart;
        if (pageGpa == 0) status = STATUS_NOT_FOUND;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_NOT_FOUND;
    }
    if (!NT_SUCCESS(status)) goto Exit;

    // 序言长度：至少覆盖 PatchLogicLen，落在指令边界。
    if (!NptHook::GetPrologueLength(
            (const uint8_t *)src + (HookPointVa & 0xFFF),
            PatchLogicLen, (uint32_t *)&prologLen) ||
        prologLen < PatchLogicLen)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // 构建 Cave。
    caveBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                              NP_RELOC_MAX_OUT + NPHV_VHOOK_MAX_LEN + 16,
                              NP_VHOOK_TAG);
    if (!caveBuf)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    status = BuildCave(src, pageVa, (ULONG)(HookPointVa & 0xFFF),
                       prologLen, (const UCHAR *)PatchLogic,
                       PatchLogicLen, (PUCHAR)caveBuf,
                       NP_RELOC_MAX_OUT + NPHV_VHOOK_MAX_LEN + 16, &caveLen);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(caveBuf, NP_VHOOK_TAG);
        goto Exit;
    }

    status = AllocateCave(ProcessId, (PUCHAR)caveBuf, caveLen,
                          &caveVa, &caveAlloc, &userCave);
    ExFreePoolWithTag(caveBuf, NP_VHOOK_TAG);
    if (!NT_SUCCESS(status)) goto Exit;

    // 登记 + 全核武装 NX。
    v = (PVHOOK_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*v), NP_VHOOK_TAG);
    if (!v)
    {
        if (userCave)
        {
            // 仍处于目标进程 attach 状态（AllocateCave 内已完成内存分配）。
            PVOID base = caveAlloc;
            SIZE_T size = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
        }
        else
        {
            ExFreePoolWithTag(caveAlloc, NP_VHOOK_TAG);
        }
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(v, sizeof(*v));
    v->Id = (ULONG)InterlockedIncrement((volatile LONG *)&g_NextId);
    v->Active = TRUE;
    v->TargetPid = ProcessId;
    v->TargetVa = HookPointVa;
    v->PageGpa = pageGpa;
    v->PageOffset = (ULONG)(HookPointVa & 0xFFF);
    v->PrologLen = prologLen;
    v->CaveVa = caveVa;
    v->CaveAlloc = caveAlloc;
    v->UserCave = userCave;
    v->CaveSize = caveLen;
    v->Mdl = mdl;

    //
    // 同页互斥：先查其它模块（各自持锁），再持本模块锁只查自己。
    // 不能在持有 g_Lock 时反向查其它模块锁（锁序反转死锁）。
    //
    if (NpHookIsPageHooked(pageGpa) ||
        NpBreakPointIsPageOccupied(pageGpa) ||
        NpDataPatchIsPageOccupied(pageGpa))
    {
        if (userCave)
        {
            PVOID base = caveAlloc;
            SIZE_T size = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
        }
        else
        {
            ExFreePoolWithTag(caveAlloc, NP_VHOOK_TAG);
        }
        ExFreePoolWithTag(v, NP_VHOOK_TAG);
        status = STATUS_ALREADY_REGISTERED;
        goto Exit;
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    if (FindByPage(pageGpa) != nullptr)
    {
        KeReleaseSpinLock(&g_Lock, irql);
        // 手动释放（此时仍 attach 目标进程，FreeEntry 会嵌套 attach）。
        if (userCave)
        {
            PVOID base = caveAlloc;
            SIZE_T size = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
        }
        else
        {
            ExFreePoolWithTag(caveAlloc, NP_VHOOK_TAG);
        }
        ExFreePoolWithTag(v, NP_VHOOK_TAG);
        status = STATUS_ALREADY_REGISTERED;
        goto Exit;
    }
    InsertTailList(&g_VHookList, &v->Link);
    KeReleaseSpinLock(&g_Lock, irql);

    for (ULONG cpu = 0; cpu < NpHvGetProcessorCount(); cpu++)
    {
        PVIRTUAL_PROCESSOR_DATA vp = nullptr;
        if (!NT_SUCCESS(NpHvGetProcessorData(cpu, &vp)) || vp == nullptr)
            continue;
        NpHookSetLeaf(vp, pageGpa, pageGpa, TRUE, TRUE);
    }

    if (OutCaveVa) *OutCaveVa = caveVa;
    if (OutId) *OutId = v->Id;
    NpHvLogPrint("[vhook] install id=%lu pid=%lu va=0x%p -> cave=0x%p "
                 "len=%lu prolog=%lu\n",
                 v->Id, ProcessId, (PVOID)HookPointVa, (PVOID)caveVa,
                 caveLen, prologLen);

Exit:
    if (attached)
    {
        KeUnstackDetachProcess(&apcState);
    }
    if (!NT_SUCCESS(status) && mdl != nullptr)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }
    if (src != nullptr) ExFreePoolWithTag(src, NP_VHOOK_TAG);
    return status;
}

NTSTATUS NpVHookUninstall(ULONG HookId)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    PVHOOK_ENTRY v = FindById(HookId);
    if (v == nullptr)
    {
        KeReleaseSpinLock(&g_Lock, irql);
        return STATUS_NOT_FOUND;
    }
    v->Active = FALSE;
    RemoveEntryList(&v->Link);
    InsertTailList(&g_RetiredList, &v->Link);
    ULONG_PTR pageGpa = v->PageGpa;
    KeReleaseSpinLock(&g_Lock, irql);

    for (ULONG cpu = 0; cpu < NpHvGetProcessorCount(); cpu++)
    {
        PVIRTUAL_PROCESSOR_DATA vp = nullptr;
        if (!NT_SUCCESS(NpHvGetProcessorData(cpu, &vp)) || vp == nullptr)
            continue;
        NpHookSetLeaf(vp, pageGpa, pageGpa, FALSE, TRUE);
    }
    NpHvLogPrint("[vhook] uninstall id=%lu\n", HookId);
    return STATUS_SUCCESS;
}

BOOLEAN NpVHookIsPageOccupied(ULONG_PTR PageGpa)
{
    KIRQL irql;
    BOOLEAN hit = FALSE;
    PageGpa &= ~(ULONG_PTR)0xFFF;
    KeAcquireSpinLock(&g_Lock, &irql);
    hit = (FindByPage(PageGpa) != nullptr);
    KeReleaseSpinLock(&g_Lock, irql);
    return hit;
}

VOID NpVHookList(PNPHV_VHOOK_LIST_RESPONSE Resp)
{
    if (Resp == nullptr) return;
    RtlZeroMemory(Resp, sizeof(*Resp));
    KIRQL irql;
    ULONG i = 0;
    KeAcquireSpinLock(&g_Lock, &irql);
    for (PLIST_ENTRY e = g_VHookList.Flink;
         e != &g_VHookList && i < NPHV_VHOOK_MAX_ENTRIES_CTL;
         e = e->Flink)
    {
        PVHOOK_ENTRY v = CONTAINING_RECORD(e, VHOOK_ENTRY, Link);
        if (!v->Active) continue;
        Resp->Entries[i].HookId = v->Id;
        Resp->Entries[i].ProcessId = v->TargetPid;
        Resp->Entries[i].TargetVa = (uint64_t)v->TargetVa;
        Resp->Entries[i].CaveVa = (uint64_t)v->CaveVa;
        Resp->Entries[i].PatchLen = v->PrologLen;
        i++;
    }
    Resp->Count = i;
    Resp->Status = STATUS_SUCCESS;
    KeReleaseSpinLock(&g_Lock, irql);
}

//
// ============================ VMEXIT ============================
//

BOOLEAN NpVHookHandleNpf(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    ULONG_PTR faultGpa = VpData->GuestVmcb.ControlArea.ExitInfo2;
    ULONG errorCode = (ULONG)(VpData->GuestVmcb.ControlArea.ExitInfo1 & MAXUINT32);
    if ((errorCode & NPF_ERROR_IFETCH) == 0) return FALSE;

    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    PVHOOK_ENTRY v = FindByPage(faultGpa);
    if (v == nullptr)
    {
        KeReleaseSpinLock(&g_Lock, irql);
        return FALSE;
    }
    BOOLEAN sameProcess = TRUE;
    if (v->TargetPid != 0)
    {
        sameProcess = (PsGetCurrentProcessId() == ULongToHandle(v->TargetPid));
    }
    ULONG_PTR rip = VpData->GuestVmcb.StateSaveArea.Rip;
    ULONG_PTR targetVa = v->TargetVa;
    ULONG_PTR caveVa = v->CaveVa;
    ULONG_PTR pageGpa = v->PageGpa;
    KeReleaseSpinLock(&g_Lock, irql);

    // 放行当前取指（原物理页可执行）；复位线程周期重武装 NX。
    NpHookSetLeaf(VpData, pageGpa, pageGpa, FALSE, TRUE);

    if (sameProcess && rip == targetVa)
    {
        // 入口命中：RIP 切到 Cave，原函数字节零修改。
        VpData->GuestVmcb.StateSaveArea.Rip = caveVa;
    }
    return TRUE;
}

BOOLEAN NpVHookHandleVmmcall(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)
{
    if ((ULONG)(Ctx->VpRegs->Rax & 0xFFFFFFFF) != VMMCALL_RESET_SHADOWS)
    {
        return FALSE;
    }
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    for (PLIST_ENTRY e = g_VHookList.Flink; e != &g_VHookList; e = e->Flink)
    {
        PVHOOK_ENTRY v = CONTAINING_RECORD(e, VHOOK_ENTRY, Link);
        if (v->Active)
        {
            NpHookSetLeaf(VpData, v->PageGpa, v->PageGpa, TRUE, TRUE);
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);
    return FALSE;       // 继续链（Hook/断点/数据补丁复位）
}
