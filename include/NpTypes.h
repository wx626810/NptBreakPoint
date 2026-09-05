/*!
    @file       NpTypes.h

    @brief      框架公共类型：Guest 寄存器、Hook 上下文、Hook 元数据、
                每 CPU 数据。与硬件描述（NpSvm.h）分离，便于上层复用。
 */
#pragma once

#include <basetsd.h>
#include <ntifs.h>
#include "NpSvm.h"

//
// ============================ Guest 寄存器 / Hook 上下文 ============================
//
// 与 x64.asm 中 PUSHAQ 的压栈顺序一致（R15 最先压入，位于低地址）。
typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rsp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

//
// 跳板回调上下文。跳板把现场填入该结构后调用回调：
//   BOOLEAN Callback(PHOOK_CALL_CONTEXT)
// 回调返回 TRUE  = 拦截（不执行原函数；可修改 Context 中的寄存器以
//                  设置返回值/影响后续行为）；
// 回调返回 FALSE = 放行（执行原函数序言副本后跳回原函数继续执行）。
//
typedef struct _HOOK_CALL_CONTEXT
{
    ULONG_PTR OriginalFunction;     // 被 Hook 的函数入口地址
    ULONG_PTR ReturnAddress;        // 调用者的返回地址（栈顶）
    ULONG_PTR Rax;                  // +0x10 以下：15 个通用寄存器
    ULONG_PTR Rcx;
    ULONG_PTR Rdx;
    ULONG_PTR Rbx;
    ULONG_PTR Rbp;
    ULONG_PTR Rsi;
    ULONG_PTR Rdi;
    ULONG_PTR R8;
    ULONG_PTR R9;
    ULONG_PTR R10;
    ULONG_PTR R11;
    ULONG_PTR R12;
    ULONG_PTR R13;
    ULONG_PTR R14;
    ULONG_PTR R15;
} HOOK_CALL_CONTEXT, *PHOOK_CALL_CONTEXT;
static_assert(sizeof(HOOK_CALL_CONTEXT) == 0x88,
              "HOOK_CALL_CONTEXT Size Mismatch");

typedef BOOLEAN(*HOOK_CALLBACK)(PHOOK_CALL_CONTEXT Context);

//
// ============================ Hook 元数据 ============================
//

//
// x64 展开表条目（wdm 头不提供；布局 = .pdata 条目，RVA 相对模块基址）
//
#ifndef _NPT_RUNTIME_FUNCTION_
#define _NPT_RUNTIME_FUNCTION_
typedef struct _NPT_RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#endif

typedef struct _HOOK_INFO
{
    LIST_ENTRY ListEntry;           // 全局 Hook 链表
    BOOLEAN Active;
    ULONG_PTR OriginalAddress;      // 被 Hook 函数 VA（Hook 点）
    ULONG_PTR OriginalPhysical;     // 被 Hook 函数所在页的 GPA（页对齐）
    ULONG PageOffset;               // 函数入口在页内的偏移
    PVOID ShadowPage0;              // 影子页0 VA：干净拷贝，NX=1（默认视图）
    PVOID ShadowPage1;              // 影子页1 VA：入口为 INT3 的拷贝，NX=0（执行视图）
    ULONG_PTR ShadowPage0PA;
    ULONG_PTR ShadowPage1PA;
    PVOID Trampoline;               // 跳板 VA（可执行、Guest 可见）
    ULONG_PTR TrampolinePA;
    UINT8 OriginalCode[16];         // 原函数序言字节副本（复制到跳板内）
    UINT8 PrologSize;               // 序言长度
    HOOK_CALLBACK Callback;         // 用户回调
    PVOID CloneVA;                  // 方案C：重定位后克隆 VA（可执行池，常驻可执行）
    PVOID CloneRaw;                 // 克隆分配原始指针（对齐前，释放用）
    ULONG CloneCodeLen;             // 重定位后代码长度（字节；< 0x4000）
    ULONG CloneTailEnd;             // 块首非重定位区域上界（前一函数尾部；
                                    //   取指低于此值走恒等+TF 单步从真页执行）
    PVOID CloneMap;                 // 偏移映射表（NP_RELOC_MAP 数组）
    ULONG CloneMapCount;            // 映射表条目数
    PRUNTIME_FUNCTION CloneUnwind;  // 方案C：克隆页展开表（偏移基于克隆基址，
                                    //   UnwindData 指向分配后段的 INFO 副本）
    ULONG CloneUnwindCount;         // 展开条目数（0 = 未建/不可精确）
} HOOK_INFO, *PHOOK_INFO;

//
// ============================ 每 CPU 数据 ============================
//

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    PVOID MsrPermissionsMap;        // 物理连续，2 页
} SHARED_VIRTUAL_PROCESSOR_DATA, *PSHARED_VIRTUAL_PROCESSOR_DATA;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        //
        //  低地址 HostStackLimit[0]                       StackLimit
        //        ...
        //        HostStackLimit[KERNEL_STACK_SIZE - 2]    StackBase
        //  高地址 HostStackLimit[KERNEL_STACK_SIZE - 1]    StackBase
        //
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 6) - sizeof(KTRAP_FRAME)];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;     // SvLaunchVm 的入口参数
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            UINT64 Padding1;        // HostRsp 16 字节对齐
            UINT64 Reserved1;       // 恒为 MAXUINT64（校验用）
        } HostStackLayout;
    };

    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];

    PNPT_ROOT NptRoot;              // 每 CPU 独立 NPT（另外分配，页对齐）
    ULONG_PTR NptRootPA;
    ULONG CpuIndex;                 // 全局 CPU 编号（0-based）

    //
    // 服务层通用挂载点：供 services/*（如 NpBreakPoint）按 CPU 存放
    // 运行状态（本字段由服务模块分配/释放，core 不触碰）。
    //
    PVOID ServiceData;
} VIRTUAL_PROCESSOR_DATA, *PVIRTUAL_PROCESSOR_DATA;
static_assert(sizeof(VIRTUAL_PROCESSOR_DATA) >= KERNEL_STACK_SIZE + PAGE_SIZE * 3,
              "VIRTUAL_PROCESSOR_DATA Size Mismatch");
