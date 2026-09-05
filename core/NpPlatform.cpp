/*!
    @file       NpPlatform.cpp

    @brief      platform 层：与 Windows 内核交互的架构无关抽象。

    @details    内存分配（页对齐/物理连续）、CPU 亲和性遍历、忙等。
                所有 core/services/demo 模块通过本层访问这些能力，
                避免散落内核 API 调用，并为未来跨架构提供隔离点。
 */
#define POOL_NX_OPTIN   1
#include "NpPlatform.h"
#include "NpLog.h"
#include <intrin.h>

//
// ============================ 内存 ============================
//

//
// 页对齐分配：ExAllocatePool2 只保证 16 字节对齐，不保证页对齐。
// VMCB/NPT_ROOT 依赖页对齐（NPT_ROOT 内 Pt[k] 页表数组按页偏移访问、
// VMCB 需物理 64 字节对齐）——此处分配 n+PAGE_SIZE，取页对齐窗口，
// 并把原始指针存到对齐指针头部，释放时还原。NpHvTeardown 等调用点不变。
//
#define NP_PAGEALIGN_HDR_SIZE   (sizeof(PVOID))

_Use_decl_annotations_
PVOID
NpAllocPageAligned(
    SIZE_T NumberOfBytes)
{
    PUCHAR raw;
    PUCHAR data;

    NT_ASSERT(NumberOfBytes >= PAGE_SIZE);
    raw = static_cast<PUCHAR>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        NumberOfBytes + PAGE_SIZE,     // 对齐余量 + 头部
                        'kpoN'));
    if (raw == nullptr)
    {
        return nullptr;
    }
    //
    // 数据区页对齐；头部 8 字节存原始指针（raw 与 data 之间必有空间）。
    //
    data = reinterpret_cast<PUCHAR>(
        (reinterpret_cast<ULONG_PTR>(raw) + NP_PAGEALIGN_HDR_SIZE +
         PAGE_SIZE - 1) & ~static_cast<ULONG_PTR>(PAGE_SIZE - 1));
    *reinterpret_cast<PVOID*>(data - NP_PAGEALIGN_HDR_SIZE) = raw;
    RtlZeroMemory(data, NumberOfBytes);
    return data;
}

_Use_decl_annotations_
VOID
NpFreePageAligned(
    PVOID BaseAddress)
{
    PVOID raw;

    if (BaseAddress == nullptr)
    {
        return;
    }
    raw = *reinterpret_cast<PVOID*>(
        reinterpret_cast<PUCHAR>(BaseAddress) - NP_PAGEALIGN_HDR_SIZE);
    ExFreePoolWithTag(raw, 'kpoN');
}

_Use_decl_annotations_
PVOID
NpAllocContiguous(
    SIZE_T NumberOfBytes)
{
    PVOID memory;
    PHYSICAL_ADDRESS boundary, lowest, highest;

    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;

    memory = MmAllocateContiguousNodeMemory(NumberOfBytes,
                                            lowest,
                                            highest,
                                            boundary,
                                            PAGE_READWRITE,
                                            MM_ANY_NODE_OK);
    if (memory != nullptr)
    {
        RtlZeroMemory(memory, NumberOfBytes);
    }
    return memory;
}

_Use_decl_annotations_
VOID
NpFreeContiguous(
    PVOID BaseAddress)
{
    MmFreeContiguousMemory(BaseAddress);
}

//
// ============================ CPU 遍历 ============================
//

_Use_decl_annotations_
NTSTATUS
NpForEachProcessor(
    NP_CPU_CALLBACK Callback,
    PVOID Context,
    PULONG NumOfProcessorCompleted)
{
    NTSTATUS status;
    ULONG numOfProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;
    ULONG i;

    if (Callback == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_SUCCESS;
    numOfProcessors = NpGetActiveProcessorCount();

    for (i = 0; i < numOfProcessors; i++)
    {
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        status = Callback(i, Context);

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

Exit:
    if (ARGUMENT_PRESENT(NumOfProcessorCompleted))
    {
        *NumOfProcessorCompleted = i;
    }
    return status;
}

_Use_decl_annotations_
ULONG
NpGetActiveProcessorCount(
    VOID)
{
    return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

//
// ============================ 忙等 ============================
//

_Use_decl_annotations_
VOID
NpStallProcessor(
    ULONG Microseconds)
{
    KeStallExecutionProcessor(Microseconds);
}
