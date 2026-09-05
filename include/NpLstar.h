#pragma once
#include <ntifs.h>
#ifdef __cplusplus
extern "C" {
#endif

// 虚拟化前调用：捕获真实 LSTAR（MSR 拦截开启前）。
NTSTATUS NpLstarPreInitialize(void);
// 虚拟化后调用：安装跳板（syscall 拦截表由 NpSyscall 解析）。
NTSTATUS NpLstarInitialize(void);
void NpLstarTeardown(void);
// 用户进程上下文（NpHvCtl IOCTL）触发：重新解析 syscall 号并热切跳板。
NTSTATUS NpLstarRefresh(void);
BOOLEAN NpLstarHandleMsr(_Inout_ struct _VIRTUAL_PROCESSOR_DATA *VpData, _Inout_ struct _GUEST_CONTEXT *Ctx, _In_ ULONG Msr, _In_ BOOLEAN IsWrite);
PVOID NpLstarGetOriginalKiSystemCall64(void);
ULONG_PTR NpLstarGetTrampolineVa(void);
BOOLEAN NpLstarIsEnabled(void);
ULONG NpLstarGetInterceptCount(void);
BOOLEAN NpLstarIsKptiActive(void);

// LSTAR 跳板 hit 路径把现场打包到该结构后调用分发器。
// 栈参数（arg5+）从 gs:[10h]（KPCR 保存的用户 RSP）读取。
typedef struct _LSTAR_SYSCALL_FRAME {
    ULONG_PTR UserRip;      // +0x00 用户返回地址（原 rcx）
    ULONG_PTR UserFlags;    // +0x08 用户 RFLAGS（原 r11）
    ULONG_PTR Arg1;         // +0x10 第一参数（原 r10 = 用户 rcx）
    ULONG_PTR Arg2;         // +0x18
    ULONG_PTR Arg3;         // +0x20
    ULONG_PTR Arg4;         // +0x28
    ULONG SyscallNumber;    // +0x30
    ULONG Reserved;
    ULONG_PTR UserRsp;      // +0x38 跳板保存的用户栈（sysretq 用）
} LSTAR_SYSCALL_FRAME, *PLSTAR_SYSCALL_FRAME;

// 私有标记：分发器置位后，跳板不 sysretq，而是恢复用户寄存器并重新
// 进入原始 KiSystemCall64（透传非受保护 syscall，避免从自定义帧调用
// 真实 Nt* 破坏调用上下文）。值避开常见 NTSTATUS。
#define NPHV_LSTAR_PASSTHROUGH  ((ULONG)0x50544C53L)   // "SLTP"

// 跳板 asm 调用的 C 分发器：完整重实现被拦截 syscall 的语义。
NTSTATUS NpLstarSyscallDispatch(_In_ ULONG SyscallNumber, _In_ PLSTAR_SYSCALL_FRAME Frame);

// VMMCALL_SYSCALL_DISPATCH 的 hypervisor 侧处理（注册 VMEXIT_VMMCALL）。
BOOLEAN NpLstarHandleVmmcall(_Inout_ struct _VIRTUAL_PROCESSOR_DATA *VpData, _Inout_ struct _GUEST_CONTEXT *Ctx);

#ifdef __cplusplus
}
#endif
