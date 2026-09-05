/*!
    @file       NpMemAccess.h

    @brief      services/NpMemAccess 对外接口：无痕内存读写。

    @details    原理（参考 kanxue《基于VT EPT的无痕断点无痕hook原理及其应用》）：
                目标 PID → 获取 CR3 → 遍历 Guest 四级页表（GVA→GPA）→
                NPT 二阶段翻译（GPA→HPA，本项目恒等映射故 GPA==HPA）→
                直接物理内存 memcpy。
                全程不经过 NtReadVirtualMemory / MmCopyVirtualMemory 等
                内存管理接口，不会被目标进程的 hook/监控察觉。

                限制：
                - 目标页必须驻留物理内存（Windows 页表页均非分页；
                  数据页若被换出到磁盘则返回 STATUS_NOT_FOUND）；
                - 读到的始终是"真实物理页"内容（即使该页被 NpHook/
                  NpBreakPoint 映射了影子页，读到的也是原始字节）。
 */
#pragma once

#include <ntifs.h>

extern "C" {

// 无痕读：把目标进程虚拟地址处 Size 字节读入 Buffer。
NTSTATUS NpMemAccessRead(
    _In_ ULONG ProcessId,              // 0 = System 进程
    _In_ ULONG_PTR VirtualAddress,
    _Out_ PVOID Buffer,
    _In_ ULONG Size,
    _Out_ PULONG BytesRead);

// 无痕写：把 Buffer 写入目标进程虚拟地址处（绕过页权限，物理直写）。
NTSTATUS NpMemAccessWrite(
    _In_ ULONG ProcessId,
    _In_ ULONG_PTR VirtualAddress,
    _In_ PVOID Buffer,
    _In_ ULONG Size,
    _Out_ PULONG BytesWritten);

// 安全用户内存拷贝（当前进程上下文）：内部用 MmCopyVirtualMemory，
// 兼容 SMAP/KPTI 下直接解引用用户指针会触发 0x50 的环境。
// 返回 STATUS_SUCCESS 表示整块拷贝完成。
NTSTATUS NpMemAccessCopyFromUser(
    _In_ ULONG_PTR UserSrc,
    _Out_ PVOID Dst,
    _In_ ULONG Size);

NTSTATUS NpMemAccessCopyToUser(
    _In_ ULONG_PTR UserDst,
    _In_ PVOID Src,
    _In_ ULONG Size);

} // extern "C"
