/*!
    @file       NpPlatform.h

    @brief      platform 层接口：与 Windows 内核交互的架构无关抽象。
                core/services/demo 通过本层访问 CPU 遍历、内存分配、
                物理地址转换，避免直接散落内核 API 调用。

                @note 本层是未来跨架构（Intel VMX/EPT）的隔离点：
                SVM 相关的硬件细节在 core/NpHv* 中，平台层只做
                “运行环境”抽象。
 */
#pragma once

#include <ntifs.h>

extern "C" {

//
// ============================ 内存 ============================
//

// 页对齐非分页池分配（清零）。4KB 对齐，物理地址可用 MmGetPhysicalAddress。
PVOID NpAllocPageAligned(
    _In_ SIZE_T NumberOfBytes);

VOID NpFreePageAligned(
    _In_ PVOID BaseAddress);

// 物理连续内存分配（清零，如 MSRPM）。
PVOID NpAllocContiguous(
    _In_ SIZE_T NumberOfBytes);

VOID NpFreeContiguous(
    _In_ PVOID BaseAddress);

//
// ============================ CPU 遍历 ============================
//

// 在所有活动处理器上执行回调（逐个绑定亲和性，PASSIVE_LEVEL）。
// 回调签名：NTSTATUS Cb(ULONG CpuIndex, PVOID Context)。
typedef NTSTATUS(*NP_CPU_CALLBACK)(_In_ ULONG CpuIndex, _In_opt_ PVOID Context);

NTSTATUS NpForEachProcessor(
    _In_ NP_CPU_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_opt_ PULONG NumOfProcessorCompleted);

// 活动处理器数量（ALL_PROCESSOR_GROUPS）。
ULONG NpGetActiveProcessorCount(
    VOID);

//
// ============================ 中断 / 状态 ============================
//

// 忙等（微秒）。VMEXIT 卸载路径等短暂窗口用。
VOID NpStallProcessor(
    _In_ ULONG Microseconds);

} // extern "C"
