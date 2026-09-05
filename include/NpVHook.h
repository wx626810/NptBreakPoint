/*!
    @file       NpVHook.h

    @brief      P4 虚拟内联钩子：
                - 原函数字节全程不改（自读/自校验/AC 读全为原始字节）；
                - 目标页 NPT NX 门控：入口取指一次 #NPF → guest RIP 切换到
                  Cave（补丁逻辑 + NpReloc 剩余块 + 跳回桩）；
                - 按目标进程 CR3 作用域分流（同页共享给其他进程时直通）；
                - 复位线程（RESET_SHADOWS）重新武装 NX，暴露窗口被压缩到
                  单次调用的执行期间。
 */
#pragma once
#include "NpConfig.h"
#include "NptHook.hpp"
#include "NpIoctl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NPHV_VHOOK_MAX_LEN   512

NTSTATUS NpVHookInitialize(void);
void NpVHookTeardown(void);

// ProcessId=0 表示内核函数（Cave 在驱动池）；否则为进程内用户地址
// （Cave 在目标进程地址空间，VAD 可见——报告 §5 已声明的残留面）。
NTSTATUS NpVHookInstall(ULONG ProcessId, ULONG_PTR HookPointVa,
                        PVOID PatchLogic, ULONG PatchLogicLen,
                        ULONG_PTR *OutCaveVa, ULONG *OutId);
NTSTATUS NpVHookUninstall(ULONG HookId);
BOOLEAN NpVHookIsPageOccupied(ULONG_PTR PageGpa);
VOID NpVHookList(_Out_ PNPHV_VHOOK_LIST_RESPONSE Resp);

// VMEXIT 处理器（NpVHookInitialize 注册）。
BOOLEAN NpVHookHandleNpf(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx);
BOOLEAN NpVHookHandleVmmcall(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx);

#ifdef __cplusplus
}
#endif
