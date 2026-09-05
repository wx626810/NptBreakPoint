/*!
    @file       NpDataPatch.h

    @brief      P5 数据补丁：
                - 读点虚拟化（主）：不碰数据字节，RVM 按观察者叠加补丁值
                  （调试器所见即所得，AC/目标读到原值）；
                - 纯数据页影子（备）：NPT not-present 翻转 + TF 单步，
                  仅适合低频数据页。
 */
#pragma once
#include "NpConfig.h"
#include "NptHook.hpp"
#include "NpIoctl.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NPHV_DATA_PATCH_READ_POINT
#define NPHV_DATA_PATCH_READ_POINT   0x00000001
#endif
#ifndef NPHV_DATA_PATCH_PAGE_SHADOW
#define NPHV_DATA_PATCH_PAGE_SHADOW  0x00000002
#endif
#define NPHV_DATA_PATCH_MAX_LEN      512

NTSTATUS NpDataPatchInitialize(void);
void NpDataPatchTeardown(void);

NTSTATUS NpDataPatchInstall(ULONG TargetPid, ULONG_PTR Va,
                            const UCHAR *Bytes, ULONG Length,
                            ULONG Flags, PULONG OutId);
NTSTATUS NpDataPatchRemove(ULONG Id);
BOOLEAN NpDataPatchIsPageOccupied(ULONG_PTR PageGpa);
VOID NpDataPatchList(_Out_ PNPHV_DATA_PATCH_LIST_RESPONSE Resp);

// 调试器视图叠加：命中则把补丁字节覆盖到 Buffer 对应区段。
BOOLEAN NpDataPatchApplyToBuffer(ULONG TargetPid, ULONG_PTR Va,
                                 PVOID Buffer, ULONG Size);

// VMEXIT 处理器（NpDataPatchInitialize 注册）。
BOOLEAN NpDataPatchHandleNpf(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx);
BOOLEAN NpDataPatchHandleDebug(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx);
BOOLEAN NpDataPatchHandleVmmcall(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx);

#ifdef __cplusplus
}
#endif
