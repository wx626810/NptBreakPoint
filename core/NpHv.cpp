/*!
    @file       NpHv.cpp

    @brief      core 层：Hypervisor 通用生命周期管理（架构无关）。

    @details    职责：
                - 每 CPU 数据数组与共享数据管理（NpHvInitialize/Teardown）
                - 生命周期事件广播（NpHvRegisterEvent）
                - 每 CPU 数据访问接口
                - 全核虚拟化 / 去虚拟化编排（具体实现委托 arch 层）
                - 影子页复位线程

                架构隔离：AMD 专属逻辑（SVM 检测、VMCB/NPT 构建、单核
                虚拟化）在 NpHvArchSvm.cpp；本文件通过 NpHvArch.h 的
                NpArch* 接口调用。未来 Intel 支持只需新增
                NpHvArchVmx.cpp，本文件与 VMEXIT 分发引擎无需改动。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpProcessHide.h"      // NpProcessHideIsStealthActive（复位线程调速）
#include "NpHvArch.h"
#include <intrin.h>

//
// ============================ 全局状态 ============================
//

static PVIRTUAL_PROCESSOR_DATA* g_VpDataArray = nullptr;
static ULONG g_NumProcessors = 0;
static volatile BOOLEAN g_HypervisorRunning = FALSE;
static volatile BOOLEAN g_ResetThreadExit = FALSE;
static volatile BOOLEAN g_ResetThreadExited = FALSE;   // 线程已真正退出（高 IRQL 忙等用）
static PSHARED_VIRTUAL_PROCESSOR_DATA g_SharedVpData = nullptr;
static HANDLE g_ResetThreadHandle = nullptr;

//
// 生命周期事件注册表（容量有限，够服务层使用）。
//
#define NP_HV_MAX_EVENT_CALLBACKS   8
typedef struct _NP_EVENT_CALLBACK_ENTRY
{
    NP_HV_EVENT_CALLBACK Callback;
    PVOID Context;
} NP_EVENT_CALLBACK_ENTRY;

static NP_EVENT_CALLBACK_ENTRY g_EventCallbacks[NpHvEventMax][NP_HV_MAX_EVENT_CALLBACKS];

//
// ============================ 事件广播 ============================
//

static
VOID
NpHvFireEvent(
    _In_ NP_HV_EVENT Event
    )
{
    for (ULONG i = 0; i < NP_HV_MAX_EVENT_CALLBACKS; i++)
    {
        if (g_EventCallbacks[Event][i].Callback != nullptr)
        {
            g_EventCallbacks[Event][i].Callback(Event,
                                                g_EventCallbacks[Event][i].Context);
        }
    }
}

_Use_decl_annotations_
NTSTATUS
NpHvRegisterEvent(
    NP_HV_EVENT Event,
    NP_HV_EVENT_CALLBACK Callback,
    PVOID Context)
{
    if (Event >= NpHvEventMax || Callback == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < NP_HV_MAX_EVENT_CALLBACKS; i++)
    {
        if (g_EventCallbacks[Event][i].Callback == nullptr)
        {
            g_EventCallbacks[Event][i].Callback = Callback;
            g_EventCallbacks[Event][i].Context = Context;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}

_Use_decl_annotations_
VOID
NpHvUnregisterEvent(
    NP_HV_EVENT Event,
    NP_HV_EVENT_CALLBACK Callback)
{
    if (Event >= NpHvEventMax || Callback == nullptr)
    {
        return;
    }
    for (ULONG i = 0; i < NP_HV_MAX_EVENT_CALLBACKS; i++)
    {
        if (g_EventCallbacks[Event][i].Callback == Callback)
        {
            g_EventCallbacks[Event][i].Callback = nullptr;
            g_EventCallbacks[Event][i].Context = nullptr;
            return;
        }
    }
}

_Use_decl_annotations_
VOID
NpHvFireEventPowerResume(
    VOID)
{
    NpHvFireEvent(NpHvEventPowerResume);
}

//
// arch 层内部接口：触发事件（单核虚拟化路径）。
//
_Use_decl_annotations_
VOID
NpHvFireEventInternal(
    NP_HV_EVENT Event)
{
    NpHvFireEvent(Event);
}

//
// ============================ 内部状态访问（arch 层） ============================
//

_Use_decl_annotations_
PVIRTUAL_PROCESSOR_DATA*
NpHvGetVpDataArrayInternal(
    VOID)
{
    return g_VpDataArray;
}

_Use_decl_annotations_
PSHARED_VIRTUAL_PROCESSOR_DATA
NpHvGetSharedVpDataInternal(
    VOID)
{
    return g_SharedVpData;
}

//
// ============================ 每 CPU 数据访问 ============================
//

_Use_decl_annotations_
NTSTATUS
NpHvGetProcessorData(
    ULONG CpuIndex,
    PVIRTUAL_PROCESSOR_DATA* OutVpData)
{
    if (OutVpData == nullptr || CpuIndex >= g_NumProcessors ||
        g_VpDataArray == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *OutVpData = g_VpDataArray[CpuIndex];
    return (*OutVpData != nullptr) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_Use_decl_annotations_
ULONG
NpHvGetProcessorCount(
    VOID)
{
    return g_NumProcessors;
}

_Use_decl_annotations_
BOOLEAN
NpHvIsRunning(
    VOID)
{
    return g_HypervisorRunning;
}

//
// ============================ 初始化 / 清理 ============================
//

_Use_decl_annotations_
NTSTATUS
NpHvInitialize(
    VOID)
{
    //
    // 分配每处理器数据数组（元素在逐核虚拟化时按需分配）。
    //
    g_NumProcessors = NpGetActiveProcessorCount();
    g_VpDataArray = static_cast<PVIRTUAL_PROCESSOR_DATA*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        sizeof(PVIRTUAL_PROCESSOR_DATA) * g_NumProcessors,
                        'kpoN'));
    if (g_VpDataArray == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_VpDataArray,
                  sizeof(PVIRTUAL_PROCESSOR_DATA) * g_NumProcessors);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
NpHvTeardown(
    VOID)
{
    //
    // 释放共享数据与每处理器数据（必须在全部 CPU 去虚拟化之后调用）。
    //
    if (g_SharedVpData != nullptr)
    {
        if (g_SharedVpData->MsrPermissionsMap != nullptr)
        {
            NpFreeContiguous(g_SharedVpData->MsrPermissionsMap);
        }
        NpFreePageAligned(g_SharedVpData);
        g_SharedVpData = nullptr;
    }

    if (g_VpDataArray != nullptr)
    {
        for (ULONG i = 0; i < g_NumProcessors; i++)
        {
            if (g_VpDataArray[i] != nullptr)
            {
                if (g_VpDataArray[i]->NptRoot != nullptr)
                {
                    NpFreePageAligned(g_VpDataArray[i]->NptRoot);
                }
                NpFreePageAligned(g_VpDataArray[i]);
                g_VpDataArray[i] = nullptr;
            }
        }
        ExFreePoolWithTag(g_VpDataArray, 'kpoN');
        g_VpDataArray = nullptr;
    }
}

//
// ============================ NPT 构建入口 ============================
//
// 统一入口：清零 + 调 arch 层构建恒等映射 + 记录根物理地址。
//

_Use_decl_annotations_
NTSTATUS
NpHvBuildNpt(
    PVIRTUAL_PROCESSOR_DATA VpData)
{
    if (VpData == nullptr || VpData->NptRoot == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(VpData->NptRoot, sizeof(NPT_ROOT));
    NpArchSvmBuildNestedPageTables(VpData->NptRoot);
    VpData->NptRootPA = MmGetPhysicalAddress(VpData->NptRoot).QuadPart;
    return STATUS_SUCCESS;
}

//
// ============================ 全核虚拟化 / 去虚拟化 ============================
//

_Use_decl_annotations_
NTSTATUS
NpHvVirtualizeAllProcessors(
    VOID)
{
    NTSTATUS status;
    ULONG numOfProcessorsCompleted;

    numOfProcessorsCompleted = 0;

    if (NpHvIsSvmSupported() == FALSE)
    {
        NpDebugPrint("SVM is not fully supported on this processor.\n");
        status = STATUS_HV_FEATURE_UNAVAILABLE;
        goto Exit;
    }

    //
    // 检查物理内存是否超出 NPT 映射范围。
    //
    {
        PHYSICAL_MEMORY_RANGE* ranges = MmGetPhysicalMemoryRanges();
        if (ranges != nullptr)
        {
            ULONG64 totalBytes = 0;
            for (PHYSICAL_MEMORY_RANGE* r = ranges;
                 r->BaseAddress.QuadPart != 0 || r->NumberOfBytes.QuadPart != 0;
                 r++)
            {
                totalBytes += static_cast<ULONG64>(r->NumberOfBytes.QuadPart);
            }
            ExFreePool(ranges);

            if (totalBytes > (ULONG64)NPTHOOK_NPT_MAP_GB * 1024 * 1024 * 1024)
            {
                NpDebugPrint("Physical memory exceeds NPT map size (%u GB).\n",
                             NPTHOOK_NPT_MAP_GB);
                status = STATUS_HV_INSUFFICIENT_BUFFERS;
                goto Exit;
            }
        }
    }

    if (g_SharedVpData == nullptr)
    {
        g_SharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(
            NpAllocPageAligned(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA)));
        if (g_SharedVpData == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        g_SharedVpData->MsrPermissionsMap = NpAllocContiguous(
            SVM_MSR_PERMISSIONS_MAP_SIZE);
        if (g_SharedVpData->MsrPermissionsMap == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        NpArchSvmBuildMsrPermissionsMap(g_SharedVpData->MsrPermissionsMap);
    }

    status = NpForEachProcessor(NpArchSvmVirtualizeProcessor,
                                nullptr,
                                &numOfProcessorsCompleted);
    if (NT_SUCCESS(status))
    {
        g_HypervisorRunning = TRUE;
    }

Exit:
    if (!NT_SUCCESS(status))
    {
        NpDebugPrint("Failed to virtualize processors (0x%08x).\n", status);
        if (numOfProcessorsCompleted > 0)
        {
            //
            // 部分处理器已虚拟化：回滚。
            //
            g_HypervisorRunning = FALSE;
            NpForEachProcessor(NpArchSvmDevirtualizeProcessor, nullptr, nullptr);
        }
    }
    return status;
}

_Use_decl_annotations_
VOID
NpHvDevirtualizeAllProcessors(
    VOID)
{
    g_HypervisorRunning = FALSE;
    NpForEachProcessor(NpArchSvmDevirtualizeProcessor, nullptr, nullptr);
}

//
// ============================ 影子页复位线程 ============================
//
// 注：复位协议通过 vmmcall 与 VMEXIT 处理器通信（AMD 专属指令）。
// 未来 Intel 支持时，此处改为 arch 提供的复位接口。
//

static
VOID
NptShadowResetThread(
    _In_ PVOID StartContext
    )
{
    UNREFERENCED_PARAMETER(StartContext);
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;
    LARGE_INTEGER interval;
    static volatile ULONG s_heartbeat = 0;

    while (!g_ResetThreadExit)
    {
        //
        // 隐匿功能活跃时收紧复位周期：hook 命中后页面进入 C 态
        // （干净可执行）直到下次复位，窗口内同核调用会绕过 hook。
        //
        ULONG resetMs = NPTHOOK_RESET_INTERVAL_MS;
        if (NpDebugHideIsEnabled() || NpProcessHideIsStealthActive())
        {
            resetMs = NPHV_STEALTH_RESET_MS;
        }

        if (g_HypervisorRunning)
        {
            for (ULONG i = 0; i < g_NumProcessors; i++)
            {
                if (g_ResetThreadExit || !g_HypervisorRunning)
                {
                    break;
                }
                if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &processorNumber)))
                {
                    break;
                }
                affinity.Group = processorNumber.Group;
                affinity.Mask = 1ULL << processorNumber.Number;
                affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
                KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

                if (g_HypervisorRunning)
                {
                    AsmVmmCallResetShadows();
                    //
                    // 竞态防御：vmmcall 期间卸载可能已置
                    // g_HypervisorRunning=FALSE（去虚拟化），此时再向
                    // 后续 CPU 发 vmmcall 会 #UD。先恢复亲和性再退出
                    // 循环（不能跳过 Revert，否则线程被钉在单核）。
                    //
                    if (!g_HypervisorRunning)
                    {
                        KeRevertToUserGroupAffinityThread(&oldAffinity);
                        break;
                    }
                }

                KeRevertToUserGroupAffinityThread(&oldAffinity);
            }
        }

        //
        // 心跳：KD 实时可见，判断冻结发生时复位线程是否仍在运行。
        //
        if ((InterlockedIncrement((volatile LONG *)&s_heartbeat) % 200) == 0)
        {
            ULONG tick = s_heartbeat / 200;
            if (tick <= 20)
            {
                NpDebugPrint("[hv] reset heartbeat tick=%lu\n", tick);
            }
        }

        interval.QuadPart = -(LONGLONG)resetMs * 10000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    g_ResetThreadExited = TRUE;         // 供高 IRQL 忙等轮询确认退出
    PsTerminateSystemThread(STATUS_SUCCESS);
}

_Use_decl_annotations_
NTSTATUS
NpHvStartShadowResetThread(
    VOID)
{
    return PsCreateSystemThread(&g_ResetThreadHandle,
                                THREAD_ALL_ACCESS,
                                nullptr,
                                nullptr,
                                nullptr,
                                NptShadowResetThread,
                                nullptr);
}

_Use_decl_annotations_
VOID
NpHvStopShadowResetThread(
    VOID)
{
    KIRQL irql;

    g_ResetThreadExit = TRUE;
    if (g_ResetThreadHandle != nullptr)
    {
        //
        // 防御：KeWaitForSingleObject 必须在 PASSIVE_LEVEL。若因卸载路径
        // 某步骤 IRQL 未恢复（bugcheck 0xA: KeWaitForSingleObject 在
        // DISPATCH_LEVEL 被调用，实测 sc stop 蓝屏），改用忙等轮询，
        // 同时打日志便于定位 IRQL 泄漏点。
        //
        irql = KeGetCurrentIrql();
        if (irql >= DISPATCH_LEVEL)
        {
            NpHvLogPrint("[hv] stop reset thread: IRQL=%u >= DISPATCH, "
                         "polling (leak suspected)\n", irql);
            for (ULONG i = 0; i < 40000 && !g_ResetThreadExited; i++)
            {
                KeStallExecutionProcessor(100);     // 100us 忙等，任何 IRQL 安全
            }
            if (!g_ResetThreadExited)
            {
                //
                // 忙等超时线程仍未退出（单核/被钉死场景）：保留句柄不关闭
                // （关闭后线程再退出会访问已释放状态 → UAF）。线程最终会
                // 自行退出，句柄泄漏远好于崩溃。
                //
                NpHvLogPrint("[hv] WARNING: reset thread did not exit in "
                             "4s, handle leaked (irql=%u)\n", irql);
                return;
            }
        }
        else
        {
            ZwWaitForSingleObject(g_ResetThreadHandle, FALSE, NULL);
        }
        ZwClose(g_ResetThreadHandle);
        g_ResetThreadHandle = nullptr;
    }
}
