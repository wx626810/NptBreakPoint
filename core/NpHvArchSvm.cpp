/*!
    @file       NpHvArchSvm.cpp

    @brief      core 层：AMD SVM 架构专属实现。

    @details    本文件包含所有绑定 AMD SVM/NPT 的逻辑：
                - SVM/NPT/SVMDIS 支持性检测（NpHvIsSvmSupported）
                - MSRPM 构建（EFER/VM_CR/VM_HSAVE_PA 反检测拦截位）
                - NPT 构建（512GB 恒等映射，2MB 大页）
                - VMCB 初始化（NptPrepareForVirtualization）
                - 单核虚拟化（进入 SvLaunchVm VM 循环）与去虚拟化

                通用生命周期在 NpHv.cpp；本文件通过 NpHvArch.h 的
                内部接口访问 NpHv.cpp 的私有状态。

                未来 Intel 支持：新增 NpHvArchVmx.cpp 实现同一组
                NpArch* 接口，NpHv.cpp / NpHvVmExit.cpp 无需改动。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpHvArch.h"
#include "NpLstar.h"
#include <intrin.h>

//
// ============================ SVM 检测 ============================
//

_Use_decl_annotations_
BOOLEAN
NpHvIsSvmSupported(
    VOID)
{
    BOOLEAN svmSupported;
    int registers[4];
    ULONG64 vmcr;

    svmSupported = FALSE;

    //
    // AMD 处理器？
    //
    __cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((registers[1] != 'htuA') ||
        (registers[3] != 'itne') ||
        (registers[2] != 'DMAc'))
    {
        goto Exit;
    }

    //
    // SVM 特性？
    //
    __cpuid(registers, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
    if ((registers[2] & CPUID_FN8000_0001_ECX_SVM) == 0)
    {
        goto Exit;
    }

    //
    // NPT 特性？
    //
    __cpuid(registers, CPUID_SVM_FEATURES);
    if ((registers[3] & CPUID_FN8000_000A_EDX_NP) == 0)
    {
        goto Exit;
    }

    //
    // SVMDIS 未锁定？
    //
    vmcr = __readmsr(SVM_MSR_VM_CR);
    if ((vmcr & SVM_VM_CR_SVMDIS) != 0)
    {
        goto Exit;
    }

    svmSupported = TRUE;

Exit:
    return svmSupported;
}

_Use_decl_annotations_
BOOLEAN
NpArchIsHypervisorInstalled(
    VOID)
{
    int registers[4];

    __cpuidex(registers, CPUID_UNLOAD_NPTHOOK, CPUID_HV_CHECK_MAGIC);
    return (registers[1] == CPUID_HV_CHECK_RETURN);
}

//
// ============================ MSRPM ============================
//

static
VOID
NptSetMsrIntercept(
    _Inout_ PVOID MsrPermissionsMap,
    _In_ ULONG Msr,
    _In_ BOOLEAN Read,
    _In_ BOOLEAN Write
    )
{
    //
    // MSRPM 布局：0x000-0x7FF 覆盖 0x00000000-0x00001FFF；
    //             0x800-0xFFF 覆盖 0xC0000000-0xC0001FFF；
    //             0x1000-0x17FF 覆盖 0xC0010000-0xC0011FFF。
    // 每个 MSR 2 位：低位=读拦截，高位=写拦截。
    //
    ULONG bitIndex;

    if (Msr <= 0x1FFF)
    {
        bitIndex = Msr * 2;
    }
    else if (Msr >= 0xC0000000 && Msr <= 0xC0001FFF)
    {
        bitIndex = 0x800 * 8 + (Msr - 0xC0000000) * 2;
    }
    else if (Msr >= 0xC0010000 && Msr <= 0xC0011FFF)
    {
        bitIndex = 0x1000 * 8 + (Msr - 0xC0010000) * 2;
    }
    else
    {
        return;
    }

    PUCHAR map = static_cast<PUCHAR>(MsrPermissionsMap);
    if (Read)
    {
        map[bitIndex / 8] |= static_cast<UCHAR>(1u << (bitIndex % 8));
    }
    if (Write)
    {
        ULONG writeIndex = bitIndex + 1;
        map[writeIndex / 8] |= static_cast<UCHAR>(1u << (writeIndex % 8));
    }
}

_Use_decl_annotations_
VOID
NpArchSvmBuildMsrPermissionsMap(
    PVOID MsrPermissionsMap)
{
    RtlZeroMemory(MsrPermissionsMap, SVM_MSR_PERMISSIONS_MAP_SIZE);

    //
    // 反检测：拦截 EFER 读写（读时隐藏 SVME，写时强制保留 SVME）、
    // VM_CR 读写（伪造 SVMDIS/LOCK）、VM_HSAVE_PA 读写（模拟未启用）。
    //
    NptSetMsrIntercept(MsrPermissionsMap, SVM_MSR_EFER, TRUE, TRUE);
    NptSetMsrIntercept(MsrPermissionsMap, SVM_MSR_VM_CR, TRUE, TRUE);
    NptSetMsrIntercept(MsrPermissionsMap, SVM_MSR_VM_HSAVE_PA, TRUE, TRUE);
    NptSetMsrIntercept(MsrPermissionsMap, 0xC0000082, TRUE, TRUE); // LSTAR RDMSR/WRMSR隐身+别名
}

//
// ============================ NPT 构建（每 CPU 恒等映射） ============================
//

_Use_decl_annotations_
VOID
NpArchSvmBuildNestedPageTables(
    PNPT_ROOT Root)
{
    ULONG_PTR pdptPa, pdPa, translationPa;

    //
    // 512GB 恒等映射：PML4[0] → PDPT → PD[i][j](2MB 大页)。
    // 上层项全部置 P/RW/US，Guest 侧所有访问（包括页表访问）不触发 NPF。
    // 权限检查由 Guest 自身页表和 NPT 两层独立完成，安全性不受影响。
    //
    for (ULONG pml4Index = 0; pml4Index < 1; pml4Index++)
    {
        pdptPa = MmGetPhysicalAddress(&Root->Pdpt[0]).QuadPart;
        Root->Pml4[pml4Index].Fields.PageFrameNumber = pdptPa >> 12;
        Root->Pml4[pml4Index].Fields.Present = 1;
        Root->Pml4[pml4Index].Fields.Write = 1;
        Root->Pml4[pml4Index].Fields.User = 1;

        for (ULONG pdptIndex = 0; pdptIndex < 512; pdptIndex++)
        {
            pdPa = MmGetPhysicalAddress(&Root->Pd[pdptIndex][0]).QuadPart;
            Root->Pdpt[pdptIndex].Fields.PageFrameNumber = pdPa >> 12;
            Root->Pdpt[pdptIndex].Fields.Present = 1;
            Root->Pdpt[pdptIndex].Fields.Write = 1;
            Root->Pdpt[pdptIndex].Fields.User = 1;

            for (ULONG pdIndex = 0; pdIndex < 512; pdIndex++)
            {
                //
                // 2MB 大页恒等：GPA == HPA。
                // PFN 字段统一按 4KB 单位（= 物理地址 >> 12）。
                //
                translationPa = (pml4Index * 512 * 512 + pdptIndex * 512 + pdIndex) *
                                (2 * 1024 * 1024ULL);
                Root->Pd[pdptIndex][pdIndex].Fields.PageFrameNumber = translationPa >> 12;
                Root->Pd[pdptIndex][pdIndex].Fields.Present = 1;
                Root->Pd[pdptIndex][pdIndex].Fields.Write = 1;
                Root->Pd[pdptIndex][pdIndex].Fields.User = 1;
                Root->Pd[pdptIndex][pdIndex].Fields.PatOrPs = 1;    // 大页
            }
        }
    }

    //
    // 记录 PT 页池各页的物理地址（供 VMEXIT 中按 PFN 反查 VA，
    // 避免在关中断上下文调用 MmGetPhysicalAddress）。
    //
    for (ULONG k = 0; k < NPTHOOK_MAX_SPLIT_PT_PER_CPU; k++)
    {
        Root->PtPhysical[k] = MmGetPhysicalAddress(&Root->Pt[k][0]).QuadPart;
    }
}

//
// ============================ 段寄存器辅助 ============================
//

static
UINT16
NptGetSegmentAccessRight(
    _In_ UINT16 SegmentSelector,
    _In_ ULONG_PTR GdtBase
    )
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
        GdtBase + (SegmentSelector & ~RPL_MASK));

    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

static
ULONG
NptGetSegmentLimit(
    _In_ UINT16 SegmentSelector
    )
{
    DESCRIPTOR_TABLE_REGISTER gdtr;
    PSEGMENT_DESCRIPTOR descriptor;
    ULONG limit;

    AsmGetGdtr(&gdtr);
    descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
        gdtr.Base + (SegmentSelector & ~RPL_MASK));
    limit = descriptor->Fields.LimitLow |
            (descriptor->Fields.LimitHigh << 16);
    if (descriptor->Fields.Granularity != 0)
    {
        limit = (limit << 12) | 0xFFF;
    }
    return limit;
}

//
// ============================ VMCB 初始化 ============================
//

static
VOID
NptPrepareForVirtualization(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData,
    _In_ const CONTEXT* ContextRecord
    )
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    PHYSICAL_ADDRESS guestVmcbPa, hostVmcbPa, hostStateAreaPa, nptPa, msrpmPa;

    AsmGetGdtr(&gdtr);
    AsmGetIdtr(&idtr);

    guestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb);
    hostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb);
    hostStateAreaPa = MmGetPhysicalAddress(&VpData->HostStateArea);
    nptPa = MmGetPhysicalAddress(VpData->NptRoot);
    msrpmPa = MmGetPhysicalAddress(SharedVpData->MsrPermissionsMap);

    //
    // 拦截：#BP（INT3，Hook/无痕断点触发）、#DB（向量 1，无痕断点的
    // TF 单步回报；未命中本框架时回落注入 Guest）、CPUID（后门/隐身）、
    // MSR 读写（MSRPM）、VMRUN（防嵌套）、VMMCALL（Hook/断点协议）、
    // SHUTDOWN（Guest 三倍错误触发关机 → 交给 VMM 而非真实关机）。
    //
    VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 3);   // #BP
    VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 1);   // #DB
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= (1UL << 31);   // SHUTDOWN
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMMCALL;
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;

    //
    // 每 CPU 独立 ASID（Hook 状态机按 CPU 独立，TLB 刷新按 ASID 隔离）。
    // ASID 取值范围 1..MaxASID（0 保留）；MaxASID = CPUID 0x8000000A.EBX。
    //
    {
        int svmRegs[4];
        ULONG maxAsid;

        __cpuid(svmRegs, CPUID_SVM_FEATURES);
        maxAsid = static_cast<ULONG>(svmRegs[1]);
        if (maxAsid < 2 || maxAsid > 0xFFFF)
        {
            maxAsid = 0xFFFF;
        }
        VpData->GuestVmcb.ControlArea.GuestAsid =
            (VpData->CpuIndex % (maxAsid - 1)) + 1;
    }
    VpData->GuestVmcb.ControlArea.TlbControl = TLB_CONTROL_FLUSH_ASID;

    //
    // 启用 NPT，NCr3 指向每 CPU 独立 NPT。
    //
    VpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    VpData->GuestVmcb.ControlArea.NCr3 = nptPa.QuadPart;

    //
    // 以当前系统状态初始化 Guest 初始状态。
    //
    VpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;

    VpData->GuestVmcb.StateSaveArea.CsLimit = NptGetSegmentLimit(ContextRecord->SegCs);
    VpData->GuestVmcb.StateSaveArea.DsLimit = NptGetSegmentLimit(ContextRecord->SegDs);
    VpData->GuestVmcb.StateSaveArea.EsLimit = NptGetSegmentLimit(ContextRecord->SegEs);
    VpData->GuestVmcb.StateSaveArea.SsLimit = NptGetSegmentLimit(ContextRecord->SegSs);
    VpData->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    VpData->GuestVmcb.StateSaveArea.CsAttrib = NptGetSegmentAccessRight(ContextRecord->SegCs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = NptGetSegmentAccessRight(ContextRecord->SegDs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = NptGetSegmentAccessRight(ContextRecord->SegEs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = NptGetSegmentAccessRight(ContextRecord->SegSs, gdtr.Base);

    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(SVM_MSR_EFER);
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = ContextRecord->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    VpData->GuestVmcb.StateSaveArea.GPat = __readmsr(SVM_MSR_PAT);

    //
    // 用 VMSAVE 把 FS/GS/TR/LDTR（含隐藏状态）以及
    // KernelGsBase/STAR/LSTAR/CSTAR/SFMASK/SYSENTER* 存入 VMCB。
    //
    __svm_vmsave(guestVmcbPa.QuadPart);

    //
    // LSTAR 预置为本核自己的 VMCB（跳板页在虚拟化前已构建）。
    // 这样每个核在各自上下文中完成安装，避免运行时跨核改活跃 VMCB。
    // KPTI 启用时不预置（syscall 入口仍在用户 CR3，跳板页不可达）。
    //
    if (!NpLstarIsKptiActive() && NpLstarGetTrampolineVa() != 0)
    {
        VpData->GuestVmcb.StateSaveArea.LStar =
            (ULONG64)NpLstarGetTrampolineVa();
    }

    //
    // Host 栈布局（SvLaunchVm 使用）。
    //
    VpData->HostStackLayout.Reserved1 = MAXUINT64;
    VpData->HostStackLayout.SharedVpData = SharedVpData;
    VpData->HostStackLayout.Self = VpData;
    VpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    VpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;

    //
    // HSAVE 区。
    //
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

    //
    // 保存 Host 状态到 Host VMCB。
    //
    __svm_vmsave(hostVmcbPa.QuadPart);
}

//
// ============================ 单核虚拟化 / 去虚拟化 ============================
//

_Use_decl_annotations_
NTSTATUS
NpArchSvmVirtualizeProcessor(
    ULONG CpuIndex,
    PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    NTSTATUS status;
    PVIRTUAL_PROCESSOR_DATA* vpDataArray;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PCONTEXT contextRecord;

    status = STATUS_SUCCESS;
    contextRecord = nullptr;
    vpData = nullptr;
    vpDataArray = NpHvGetVpDataArrayInternal();
    sharedVpData = NpHvGetSharedVpDataInternal();

    //
    // 首次虚拟化时分配每处理器数据（电源恢复后复用）。
    //
    if (vpDataArray[CpuIndex] == nullptr)
    {
        vpData = static_cast<PVIRTUAL_PROCESSOR_DATA>(
            NpAllocPageAligned(sizeof(VIRTUAL_PROCESSOR_DATA)));
        if (vpData == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        vpData->NptRoot = static_cast<PNPT_ROOT>(
            NpAllocPageAligned(sizeof(NPT_ROOT)));
        if (vpData->NptRoot == nullptr)
        {
            NpFreePageAligned(vpData);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        vpData->CpuIndex = CpuIndex;
        vpDataArray[CpuIndex] = vpData;
    }
    vpData = vpDataArray[CpuIndex];

    //
    // 重建 NPT（恒等映射；电源恢复后需要全新状态）。
    //
    status = NpHvBuildNpt(vpData);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    contextRecord = static_cast<PCONTEXT>(ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                          sizeof(*contextRecord),
                                                          'kpoN'));
    if (contextRecord == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // 捕获当前状态：VMRUN 之后 Guest 从这里（本函数 if 判断处）继续执行。
    //
    RtlCaptureContext(contextRecord);

    if (NpArchIsHypervisorInstalled() == FALSE)
    {
        //
        // 启用 SVM 并虚拟化本处理器。
        //
        __writemsr(SVM_MSR_EFER, __readmsr(SVM_MSR_EFER) | EFER_SVME);
        NpHvFireEventInternal(NpHvEventVirtualizeBegin);
        NptPrepareForVirtualization(vpData, sharedVpData, contextRecord);
        NpHvLogPrint("Virtualizing processor #%lu...\n", CpuIndex);
        SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        //
        // 正常情况下不会执行到这里（SvLaunchVm 不返回）。
        //
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0, 0, 0, 0);
    }

    //
    // 虚拟化后的续跑路径：本处理器已被虚拟化。
    //
    NpHvFireEventInternal(NpHvEventVirtualizeEnd);
    status = STATUS_SUCCESS;

Exit:
    if (contextRecord != nullptr)
    {
        ExFreePoolWithTag(contextRecord, 'kpoN');
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS
NpArchSvmDevirtualizeProcessor(
    ULONG CpuIndex,
    PVOID Context)
{
    UNREFERENCED_PARAMETER(CpuIndex);
    UNREFERENCED_PARAMETER(Context);
    int registers[4];

    //
    // 请求 Hypervisor 卸载。若已虚拟化，ECX 将返回 'NPTU'。
    // VpData 由调用方在全部处理器去虚拟化后统一释放。
    //
    __cpuidex(registers, CPUID_UNLOAD_NPTHOOK, CPUID_UNLOAD_MAGIC);
    if (registers[2] == 'NPTU')
    {
        // 已回到非虚拟化上下文：恢复真实 LSTAR（本核自己的 MSR）。
        __writemsr(SVM_MSR_LSTAR, (ULONG64)NpLstarGetOriginalKiSystemCall64());
        NpDebugPrint("Processor de-virtualized.\n");
    }
    return STATUS_SUCCESS;
}
