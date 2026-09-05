/*!
    @file       NpAsm.h

    @brief      x64.asm 导出符号的统一声明。所有汇编入口集中在此，
                C/C++ 侧禁止散落声明。
 */
#pragma once

#include <ntifs.h>

extern "C" {

//
// VM 循环：进入“执行 Guest / 处理 #VMEXIT”循环，直至请求卸载。
// 卸载后返回到触发 #VMEXIT 的指令的下一条。
//
VOID NTAPI SvLaunchVm(_In_ PVOID HostRsp);

//
// Guest 侧 vmmcall 封装：请求 Hypervisor 复位当前 CPU 的影子页。
//
VOID AsmVmmCallResetShadows(VOID);

//
// Guest 侧 vmmcall 封装：继续被暂停的断点（rcx = BpId，0 = 全部）。
//
VOID AsmVmmCallBpContinue(_In_ ULONG64 BpId);

//
// Guest 侧 vmmcall 封装：开启/关闭 DR 探测（rcx = 0/1）。
//
VOID AsmVmmCallDrProbe(_In_ ULONG64 Enable);

//
// Guest 侧 vmmcall 封装：请求 Hypervisor 继续被暂停的无痕断点。
// rcx = BpId（0 = 全部被暂停的断点）。必须在断点暂停所在 CPU
// （BREAKPOINT_INFO.HaltCpu）上调用（修改 VMCB 需在本 CPU VMEXIT 上下文）。
//
VOID AsmVmmCallBpContinue(_In_ ULONG64 BpId);

//
// 读取 GDTR/IDTR（写 10 字节描述符表寄存器结构）。
//
VOID AsmGetGdtr(_Out_ PVOID Descriptor);
VOID AsmGetIdtr(_Out_ PVOID Descriptor);

//
// 跳板模板（可整体拷贝到可执行池）。
//
VOID TrampolineTemplate(VOID);
extern ULONG TrampolineTemplateSize;

// 跳板模板内数据区偏移（由 x64.asm 定义，Hook 构建时修补指针）。
#define TRAMPOLINE_DATA_HOOKFUNC_OFF      0x0100
#define TRAMPOLINE_DATA_ORIGINAL_OFF      0x0108
#define TRAMPOLINE_DATA_AFTERPROLOG_OFF   0x0110
#define TRAMPOLINE_DATA_PROLOG_OFF        0x0118
#define JUMPBACK_STUB_SIZE                12

} // extern "C"
