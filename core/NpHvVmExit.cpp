/*!
    @file       NpHvVmExit.cpp

    @brief      core 层：VMEXIT 分发引擎。

    @details    职责：
                - VMEXIT 分发（NptHandleVmExit，由 x64.asm 调用）
                - **handler 注册表**：新功能通过 NpHvRegisterVmExitHandler
                  注册，handler 返回 TRUE 表示已处理，FALSE 回落到内置逻辑。
                - 内置处理器：CPUID（后门/隐身）、MSR（反检测）、NPF/#BP
                  （Hook 状态机）、VMMCALL、VMRUN（防嵌套）、SHUTDOWN
                - 异常注入（EventInj 构造）

                扩展示例（新增 VMEXIT 监控）：
                    NpHvRegisterVmExitHandler(VMEXIT_CPUID, MyCpuidHook);
                你的 handler 在核心处理之前被调用，可检查/修改 VpRegs。
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include <intrin.h>
#include "NpLstar.h"
#include "NpDebugHide.h"
#include "NpProcessHide.h"
extern PUNICODE_STRING NpDevGetDosDeviceName(void);

//
// ============================ handler 注册表 ============================
//

#define NP_MAX_VMEXIT_HANDLERS  32
#define NP_WATCHDOG_MAX         5000000

// VMEXIT 风暴看门狗：同一 (exitCode, Rip, Info2) 连续重复超阈值即
// KeBugCheck 出转储（KD 无法 break 的 host 空转场景唯一可读现场）。
static ULONG64 g_WdExit = 0;
static ULONG64 g_WdRip = 0;
static ULONG64 g_WdInfo2 = 0;
static ULONG g_WdCount = 0;

typedef struct _NP_VMEXIT_ENTRY
{
    ULONG ExitCode;
    NP_VMEXIT_HANDLER Handler;
} NP_VMEXIT_ENTRY;

static NP_VMEXIT_ENTRY g_VmExitHandlers[NP_MAX_VMEXIT_HANDLERS];
static ULONG g_VmExitHandlerCount = 0;
static KSPIN_LOCK g_VmExitHandlerLock;

// 后置回调：VMEXIT 分发完成后、返回 Guest 前逐个调用（缩小 CC 窗口用）。
#define NP_MAX_POST_EXIT_CALLBACKS  4
static NP_POST_EXIT_CALLBACK g_PostExitCallbacks[NP_MAX_POST_EXIT_CALLBACKS];
static ULONG g_PostExitCallbackCount = 0;
static KSPIN_LOCK g_PostExitCallbackLock;

/*!
    @brief      注册 VMEXIT handler。同一 ExitCode 可注册多个
                （先注册先调用；任一返回 TRUE 即终止链）。

    @return     STATUS_SUCCESS / STATUS_INSUFFICIENT_RESOURCES。
 */
_Use_decl_annotations_
NTSTATUS
NpHvRegisterVmExitHandler(
    ULONG ExitCode,
    NP_VMEXIT_HANDLER Handler)
{
    KIRQL oldIrql;
    NTSTATUS status;

    if (Handler == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_VmExitHandlerLock, &oldIrql);
    if (g_VmExitHandlerCount >= NP_MAX_VMEXIT_HANDLERS)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        g_VmExitHandlers[g_VmExitHandlerCount].ExitCode = ExitCode;
        g_VmExitHandlers[g_VmExitHandlerCount].Handler = Handler;
        g_VmExitHandlerCount++;
        KeMemoryBarrier();                      // VMEXIT 热路径无锁读，写侧需屏障
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_VmExitHandlerLock, oldIrql);
    return status;
}

/*!
    @brief      调用与 ExitCode 匹配的已注册 handler。
    @return     TRUE = 已有 handler 处理完成；FALSE = 无 handler，走内置逻辑。

    @note       handler 注册表仅在驱动初始化期写入（NpHvRegisterVmExitHandler
                带锁 + 内存屏障），运行期只读——VMEXIT 热路径无锁遍历，
                避免每次 VMEXIT 的自旋锁串行化（多核 DPC 延迟）。
 */
_Use_decl_annotations_
NTSTATUS
NpHvRegisterPostExitCallback(
    NP_POST_EXIT_CALLBACK Callback)
{
    KIRQL oldIrql;
    NTSTATUS status;

    if (Callback == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_PostExitCallbackLock, &oldIrql);
    if (g_PostExitCallbackCount >= NP_MAX_POST_EXIT_CALLBACKS)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        g_PostExitCallbacks[g_PostExitCallbackCount++] = Callback;
        KeMemoryBarrier();                  // VMEXIT 热路径无锁读，写侧需屏障
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_PostExitCallbackLock, oldIrql);
    return status;
}

static
BOOLEAN
NpHvInvokeVmExitHandlers(
    _In_ ULONG ExitCode,
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    BOOLEAN handled = FALSE;

    KeMemoryBarrier();                          // 确保看到初始化期全部写入
    for (ULONG i = 0; i < g_VmExitHandlerCount; i++)
    {
        if (g_VmExitHandlers[i].ExitCode == ExitCode)
        {
            if (g_VmExitHandlers[i].Handler(VpData, GuestContext))
            {
                handled = TRUE;
                break;
            }
        }
    }
    return handled;
}

//
// ============================ 异常注入 ============================
//

static
VOID
NptInjectException(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ UINT16 Vector,
    _In_ UINT8 Type,
    _In_ BOOLEAN ErrorCodeValid,
    _In_ ULONG ErrorCode
    )
{
    EVENTINJ event;

    event.AsUInt64 = 0;
    event.Fields.Vector = Vector;
    event.Fields.Type = Type;
    event.Fields.ErrorCodeValid = ErrorCodeValid ? 1 : 0;
    event.Fields.Valid = 1;
    event.Fields.ErrorCode = ErrorCode;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

static
VOID
NptInjectGeneralProtectionException(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    NptInjectException(VpData, 13, 3, TRUE, 0);
}

static
VOID
NptInjectBreakpoint(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    NptInjectException(VpData, 3, 3, FALSE, 0);
}

static
VOID
NptInjectPageFault(
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ ULONG ErrorCode,
    _In_ ULONG_PTR FaultAddress
    )
{
    //
    // AMD APM Vol.2：EVENTINJ 注入 #PF 时，CR2 取自 VMCB 保存区。
    // 必须先写入本次故障地址——否则 Guest 收到上一次遗留的陈旧 CR2，
    // 内核页错误处理判定错乱（内存管理误判 → Guest 蓝屏）。
    // 注：NPF 的 ExitInfo2 是 GPA；精确 GVA 需反查 Guest 页表，
    // 此处取故障 GPA 作尽力值（该路径本为"不应发生"的兜底）。
    //
    VpData->GuestVmcb.StateSaveArea.Cr2 = FaultAddress;
    NptInjectException(VpData, 14, 3, TRUE, ErrorCode);
}

//
// ============================ 内置处理器：CPUID ============================
//

static
VOID
NptHandleCpuid(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    int registers[4];
    int leaf, subLeaf;
    SEGMENT_ATTRIBUTE attribute;

    leaf = static_cast<int>(GuestContext->VpRegs->Rax);
    subLeaf = static_cast<int>(GuestContext->VpRegs->Rcx);
    __cpuidex(registers, leaf, subLeaf);

    switch (leaf)
    {
    case CPUID_UNLOAD_NPTHOOK:
        if (subLeaf == CPUID_UNLOAD_MAGIC)
        {
            //
            // 卸载后门：仅 CPL 0。
            //
            attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
            if (attribute.Fields.Dpl == DPL_SYSTEM)
            {
                GuestContext->ExitVm = TRUE;
            }
        }
        else if (subLeaf == CPUID_HV_CHECK_MAGIC)
        {
            //
            // 内部检测：标记“Hypervisor 已安装”。
            //
            registers[1] = CPUID_HV_CHECK_RETURN;
        }
        break;

#if !NPTHOOK_STEALTH
    case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS:
        //
        // 非隐身模式：设置 Hypervisor Present 位，便于验证。
        //
        registers[2] |= CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT;
        break;
    case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
        //
        // 报告厂商 "NptHook   "。
        //
        registers[0] = 0;
        registers[1] = 'pHtN';  // "NptH"
        registers[2] = 0x206B6F6F;  // "ook "
        registers[3] = 0x20202020;  // "    "
        break;
#endif

    default:
        break;
    }

    GuestContext->VpRegs->Rax = registers[0];
    GuestContext->VpRegs->Rbx = registers[1];
    GuestContext->VpRegs->Rcx = registers[2];
    GuestContext->VpRegs->Rdx = registers[3];

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

//
// ============================ 内置处理器：MSR ============================
//

static
VOID
NptHandleMsrAccess(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    ULARGE_INTEGER value;
    UINT32 msr;
    BOOLEAN writeAccess;

    msr = static_cast<UINT32>(GuestContext->VpRegs->Rcx & MAXUINT32);
    //
    // AMD：MSR 拦截时 ExitInfo1 bit0 = 1 表示 WRMSR（bit0=0 为 RDMSR）。
    //
    writeAccess = ((VpData->GuestVmcb.ControlArea.ExitInfo1 & 1) != 0);

    if (msr == SVM_MSR_EFER)
    {
        if (writeAccess)
        {
            value.LowPart = static_cast<ULONG>(GuestContext->VpRegs->Rax & MAXUINT32);
            value.HighPart = static_cast<ULONG>(GuestContext->VpRegs->Rdx & MAXUINT32);

            //
            // 强制保留 SVME（Guest 无法关闭 SVM）。
            //
            value.QuadPart |= EFER_SVME;
            __writemsr(SVM_MSR_EFER, value.QuadPart);
            VpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
        }
        else
        {
            //
            // 读 EFER 时隐藏 SVME：Guest 看到“SVM 未启用”。
            //
            value.QuadPart = __readmsr(SVM_MSR_EFER);
            value.QuadPart &= ~EFER_SVME;
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    else if (msr == SVM_MSR_VM_CR)
    {
        if (writeAccess)
        {
            //
            // 模拟 SVME=0 时对 VM_CR 的写入：注入 #GP。
            //
            NptInjectGeneralProtectionException(VpData);
            return;
        }
        else
        {
            //
            // 伪造“BIOS 已锁定 SVM”的状态。
            //
            value.QuadPart = __readmsr(SVM_MSR_VM_CR);
            value.QuadPart |= SVM_VM_CR_SVMDIS | SVM_VM_CR_LOCK;
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }
    else if (msr == 0xC0000082) // LSTAR
    {
        extern BOOLEAN NpLstarHandleMsr(struct _VIRTUAL_PROCESSOR_DATA*, struct _GUEST_CONTEXT*, ULONG, BOOLEAN);
        if(NpLstarHandleMsr(VpData, GuestContext, msr, writeAccess)) { VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; return; }
        // NpLstarHandleMsr 未处理（理论不应发生）时直通。
        if(writeAccess){ ULARGE_INTEGER v; v.LowPart=(ULONG)(GuestContext->VpRegs->Rax & 0xFFFFFFFF); v.HighPart=(ULONG)(GuestContext->VpRegs->Rdx & 0xFFFFFFFF); __writemsr(msr,v.QuadPart);} else { ULARGE_INTEGER v; v.QuadPart=__readmsr(msr); GuestContext->VpRegs->Rax=v.LowPart; GuestContext->VpRegs->Rdx=v.HighPart; }
    }
    else if (msr == SVM_MSR_VM_HSAVE_PA)
    {
        if (writeAccess)
        {
            NptInjectGeneralProtectionException(VpData);
            return;
        }
        else
        {
            //
            // 模拟 SVM 未启用：返回 0。
            //
            GuestContext->VpRegs->Rax = 0;
            GuestContext->VpRegs->Rdx = 0;
        }
    }
    else
    {
        //
        // 其他 MSR 直通。注意：Guest 访问未实现的 MSR 会导致
        // __readmsr/__writemsr 抛 #GP，本代码无法用 SEH 保护
        // （VMEXIT 上下文不在线程栈上）。若遇到此类问题，
        // 可改为对未知 MSR 返回 0/忽略写。
        //
        if (writeAccess)
        {
            value.LowPart = static_cast<ULONG>(GuestContext->VpRegs->Rax & MAXUINT32);
            value.HighPart = static_cast<ULONG>(GuestContext->VpRegs->Rdx & MAXUINT32);
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

//
// ============================ 内置处理器：VMRUN / NPF / #BP / VMMCALL / SHUTDOWN ============================
//

static
VOID
NptHandleVmrun(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    UNREFERENCED_PARAMETER(GuestContext);

    //
    // 不支持嵌套虚拟化。
    //
    NptInjectGeneralProtectionException(VpData);
}

static
VOID
NptHandleNestedPageFault(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    ULONG_PTR faultGpa = VpData->GuestVmcb.ControlArea.ExitInfo2;
    ULONG_PTR faultRip = VpData->GuestVmcb.StateSaveArea.Rip;
    ULONG errorCode = static_cast<ULONG>(VpData->GuestVmcb.ControlArea.ExitInfo1 & MAXUINT32);

    if ((errorCode & NPF_ERROR_PRESENT) == 0)
    {
        //
        // 未映射的 GPA：NPT 已完整覆盖 512GB，不应发生。注入 #PF。
        //
        NptInjectPageFault(VpData, errorCode, faultGpa);
        return;
    }

    if (errorCode & NPF_ERROR_IFETCH)
    {
        //
        // 取指违例：交给 Hook 状态机。
        //
        if (NpHookHandleNpf(VpData, faultGpa, faultRip, errorCode))
        {
            return;
        }

        //
        // 未知页的取指违例（安装/卸载竞态等）：自愈——恢复恒等映射。
        //
        NpHookRestoreIdentity(VpData, faultGpa & ~static_cast<ULONG_PTR>(0xFFF));
        return;
    }

    //
    // 读/写违例：先交给 Hook 引擎（方案C 下被_hook 页叶子常驻 NX，
    // 数据访问在此收口：恒等+TF 单步一条指令后自动回武装态）。
    // 非框架页回落注入 #PF。
    //
    if (NpHookHandleDataFault(VpData, faultGpa, errorCode))
    {
        return;
    }

    NptInjectPageFault(VpData, errorCode, faultGpa);
}

static
VOID
NptHandleDebugException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    //
    // 方案C：Hook 数据单步的 #DB 收口（优先尝试——只在挂起标志置位时
    // 消费，与断点单步互不干扰）。
    //
    if (NpHookHandleDebugStep(VpData))
    {
        return;
    }

    //
    // 非本框架的 #DB（NpBreakPoint 单步未命中时走到这里）：
    // 转发给 Guest（内核调试器/自研单步场景）。
    //
    NptInjectException(VpData, 1, 3, FALSE, 0);
}

static
VOID
NptHandleBreakpoint(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    //
    // 命中 Hook：RIP 被重定向到跳板。
    //
    if (NpHookHandleBreakpoint(VpData))
    {
        return;
    }

    //
    // 非框架的 INT3：转发给 Guest（内核调试器场景）。
    // 注入 #BP 前把 RIP 推进到 INT3 之后（NRip）——注入事件以 VMCB.Rip
    // 作为异常返回地址；若不推进，调试器 continue 后会重新执行 INT3，
    // 形成无限断点循环（AMD：拦截时 Rip=INT3、NRip=INT3+1）。
    //
    VpData->GuestVmcb.StateSaveArea.Rip =
        VpData->GuestVmcb.ControlArea.NRip;
    NptInjectBreakpoint(VpData);
}

static
VOID
NptHandleVmmcall(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    // Hypercall from CPL3 (R3) allowed for magic range 0x4E505640..4F (rolling low byte = cookie)
    const ULONG64 HC_COOKIE = 0x5A; // must match R3 g_HcCookie low byte
    if (VpData->GuestVmcb.StateSaveArea.Cpl != 0)
    {
        ULONG64 _rax = GuestContext->VpRegs->Rax ^ HC_COOKIE; // unroll
        if (_rax < VMMCALL_HYPERCALL_BASE || _rax > VMMCALL_HYPERCALL_MAX)
        {
            NptInjectGeneralProtectionException(VpData);
            return;
        }
        GuestContext->VpRegs->Rax = _rax; // restore original for switch
    }

    switch (GuestContext->VpRegs->Rax)
    {
    case VMMCALL_RESET_SHADOWS:
        //
        // 复位本 CPU 全部影子页到状态 A（读/写视图 + NX=1）。
        //
        NpHookResetAllShadows(VpData);
        break;
    case VMMCALL_HYPERCALL_PING:
        GuestContext->VpRegs->Rax = 0x4E505641; // pong
        break;
    case VMMCALL_HYPERCALL_QUERY_STATUS:
        {
            extern ULONG NpHvGetProcessorCount(void);
            extern ULONG NpHookGetActiveCount(void);
            // NpSelfHideIsEnabled 已由 NptHook.hpp→NpHv.h（extern "C"）声明
            GuestContext->VpRegs->Rax = 0;
            GuestContext->VpRegs->Rbx = NPHV_PROTOCOL_VERSION;
            GuestContext->VpRegs->Rcx = 1;
            GuestContext->VpRegs->Rdx = (ULONG64)NpHvGetProcessorCount();
            GuestContext->VpRegs->R8  = (ULONG64)NpHookGetActiveCount();
            GuestContext->VpRegs->R9  = 0;
            // 修复：此前硬编码 0，导致 R3 永远显示"自隐藏:关"（实为编译期已开启）
            GuestContext->VpRegs->R10 = NpSelfHideIsEnabled() ? 0x00000001u : 0;
        }
        break;
    case VMMCALL_HYPERCALL_GET_DEVICE_NAME:
        {
            PUNICODE_STRING dos = NpDevGetDosDeviceName();
            GuestContext->VpRegs->Rax = 0;
            if (dos && dos->Buffer && dos->Length > 0) {
                // Pack DosDevice name (e.g., \DosDevices\NpHv_XXXXXXXX) into Rbx..R11 (7 regs *8 =56 bytes =28 wchar)
                // Zero first
                GuestContext->VpRegs->Rbx = 0; GuestContext->VpRegs->Rcx = 0; GuestContext->VpRegs->Rdx = 0;
                GuestContext->VpRegs->R8 = 0; GuestContext->VpRegs->R9 = 0; GuestContext->VpRegs->R10 = 0; GuestContext->VpRegs->R11 = 0;
                ULONG copyLen = dos->Length; if (copyLen > 56) copyLen = 56;
                // Copy as bytes into registers
                unsigned char tmp[56]={0};
                for(ULONG i=0;i<copyLen;i++) tmp[i] = ((unsigned char*)dos->Buffer)[i];
                // Pack little-endian into regs
                GuestContext->VpRegs->Rbx = *(UINT64*)&tmp[0];
                GuestContext->VpRegs->Rcx = *(UINT64*)&tmp[8];
                GuestContext->VpRegs->Rdx = *(UINT64*)&tmp[16];
                GuestContext->VpRegs->R8  = *(UINT64*)&tmp[24];
                GuestContext->VpRegs->R9  = *(UINT64*)&tmp[32];
                GuestContext->VpRegs->R10 = *(UINT64*)&tmp[40];
                GuestContext->VpRegs->R11 = *(UINT64*)&tmp[48];
                // Also return length in Rax high? Use Rax=0 success, length in low 32 of Rax? Keep Rax=0, length via extra? Use Rax low = length
                GuestContext->VpRegs->Rax = (UINT64)copyLen;
            } else {
                GuestContext->VpRegs->Rax = (UINT64)0xC0000001; // error
            }
        }
        break;
    case VMMCALL_HYPERCALL_DBG_HIDE:
        {
            BOOLEAN enable = (GuestContext->VpRegs->Rbx & 1) ? TRUE : FALSE;
            if(NpLstarIsEnabled()){
                NTSTATUS st1 = NpDebugHideSetEnabled(enable);
                NTSTATUS st2 = NpProcessHideSetEnabled(enable);
                NTSTATUS st = NT_SUCCESS(st1) ? st2 : st1;
                GuestContext->VpRegs->Rax = (UINT64)st;
                NpHvLogPrint("[hc] DbgHide sync enable=%u st=0x%08x\n", (ULONG)enable, st);
            } else {
                NTSTATUS st = NpDebugHideQueueEnable(enable);
                GuestContext->VpRegs->Rax = (UINT64)st;
                NpHvLogPrint("[hc] DbgHide queued enable=%u st=0x%08x\n", (ULONG)enable, st);
            }
        }
        break;
    case VMMCALL_HYPERCALL_DBG_PROTECT:
        {
            ULONG pid = (ULONG)GuestContext->VpRegs->Rbx;
            BOOLEAN prot = (GuestContext->VpRegs->Rcx & 1) ? TRUE : FALSE;
            NTSTATUS st = NpDebugHideProtectProcess(pid, prot);
            GuestContext->VpRegs->Rax = (UINT64)st;
            NpHvLogPrint("[hc] DbgProtect pid=%lu prot=%u st=0x%08x\n", pid, (ULONG)prot, st);
        }
        break;
    case VMMCALL_HYPERCALL_DBG_MODE:
        {
            ULONG mode = (ULONG)GuestContext->VpRegs->Rbx;
            NTSTATUS st = NpDebugHideSetMode(mode);
            GuestContext->VpRegs->Rax = (UINT64)st;
            NpHvLogPrint("[hc] DbgMode mode=%lu st=0x%08x\n", mode, st);
        }
        break;

    default:
        break;
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

static
VOID
NptHandleShutdown(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    UNREFERENCED_PARAMETER(VpData);
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0, 0, 0, 0);
}

//
// ============================ VMEXIT 分发 ============================
//

_IRQL_requires_same_
EXTERN_C
BOOLEAN
NTAPI
NptHandleVmExit(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_REGISTERS GuestRegisters
    )
{
    GUEST_CONTEXT guestContext;
    KIRQL oldIrql;
    ULONG64 wdExitCode;

    guestContext.VpRegs = GuestRegisters;
    guestContext.ExitVm = FALSE;

    //
    // 加载 #VMEXIT 未保存的 Host 状态。
    //
    __svm_vmload(VpData->HostStackLayout.HostVmcbPa);

    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);

    //
    // 提升 IRQL 到 DISPATCH_LEVEL（关中断上下文；此操作实为写 CR8，
    // 在此上下文安全）。主要价值是让 Driver Verifier 拦截不安全的调用。
    //
    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }

    //
    // #VMEXIT 时 RAX 被 Host 值覆盖并保存到 VMCB，这里恢复给上下文。
    //
    GuestRegisters->Rax = VpData->GuestVmcb.StateSaveArea.Rax;

    //
    // 看门狗：连续相同 VMEXIT 检测（放在分发前，任何 handler 空转都能抓住）。
    //
    wdExitCode = VpData->GuestVmcb.ControlArea.ExitCode;
    if (wdExitCode == g_WdExit &&
        VpData->GuestVmcb.StateSaveArea.Rip == g_WdRip &&
        VpData->GuestVmcb.ControlArea.ExitInfo2 == g_WdInfo2)
    {
        // 断点 HALT 钉住线程会产生连续相同的 #NPF，这是设计行为；
        // 命中 Halted 断点页时清零计数，避免看门狗误判为死循环蓝屏。
        if (wdExitCode == VMEXIT_NPF &&
            NpBreakPointIsHaltedPage(
                VpData->GuestVmcb.ControlArea.ExitInfo2))
        {
            g_WdCount = 0;
        }
        else if (++g_WdCount >= NP_WATCHDOG_MAX)
        {
            KeBugCheckEx(0xDEAD0001,
                         wdExitCode,
                         VpData->GuestVmcb.StateSaveArea.Rip,
                         VpData->GuestVmcb.ControlArea.ExitInfo2,
                         g_WdCount);
        }
        if ((g_WdCount % 1000000) == 0)
        {
            NpHvLogPrint("[hv] watchdog %lu exit=0x%llx rip=0x%llx\n",
                         g_WdCount,
                         (unsigned long long)wdExitCode,
                         (unsigned long long)VpData->GuestVmcb.StateSaveArea.Rip);
        }
    }
    else
    {
        g_WdExit = wdExitCode;
        g_WdRip = VpData->GuestVmcb.StateSaveArea.Rip;
        g_WdInfo2 = VpData->GuestVmcb.ControlArea.ExitInfo2;
        g_WdCount = 0;
    }

    //
    // 更新 _KTRAP_FRAME，便于 Windbg 重建 Guest 调用栈。
    //
    VpData->HostStackLayout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->HostStackLayout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;

    //
    // 分发：先查 handler 注册表（新功能），未处理则走内置逻辑。
    //
    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_CPUID, VpData, &guestContext))
        {
            NptHandleCpuid(VpData, &guestContext);
        }
        break;
    case VMEXIT_MSR:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_MSR, VpData, &guestContext))
        {
            NptHandleMsrAccess(VpData, &guestContext);
        }
        break;
    case VMEXIT_VMRUN:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_VMRUN, VpData, &guestContext))
        {
            NptHandleVmrun(VpData, &guestContext);
        }
        break;
    case VMEXIT_NPF:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_NPF, VpData, &guestContext))
        {
            NptHandleNestedPageFault(VpData);
        }
        break;
    case VMEXIT_EXCEPTION_BP:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_EXCEPTION_BP, VpData, &guestContext))
        {
            NptHandleBreakpoint(VpData);
        }
        break;
    case VMEXIT_EXCEPTION_DB:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_EXCEPTION_DB, VpData, &guestContext))
        {
            NptHandleDebugException(VpData);
        }
        break;
    case VMEXIT_VMMCALL:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_VMMCALL, VpData, &guestContext))
        {
            NptHandleVmmcall(VpData, &guestContext);
        }
        break;
    case VMEXIT_SHUTDOWN:
        if (!NpHvInvokeVmExitHandlers(VMEXIT_SHUTDOWN, VpData, &guestContext))
        {
            NptHandleShutdown(VpData);
        }
        break;
    default:
        if (!NpHvInvokeVmExitHandlers(
                static_cast<ULONG>(VpData->GuestVmcb.ControlArea.ExitCode),
                VpData,
                &guestContext))
        {
            //
            // 未知 VMEXIT：不再蓝屏——记录并恢复执行（Rip=NRip）。
            // 未识别的 exit code 不应导致整个系统崩溃；若某拦截位
            // 残留/新处理器未注册，Guest 继续执行语义仍正确。
            //
            // VMEXIT 上下文禁用 DbgPrint（KD 传输可能在 GIF=0 下死锁），
            // 只写环形日志，由落盘线程在 PASSIVE 上下文冲刷。
            NpHvLogPrint("Unexpected VMEXIT code: 0x%llx (info1=0x%llx, "
                         "info2=0x%llx) - recovering\n",
                         (unsigned long long)VpData->GuestVmcb.ControlArea.ExitCode,
                         (unsigned long long)VpData->GuestVmcb.ControlArea.ExitInfo1,
                         (unsigned long long)VpData->GuestVmcb.ControlArea.ExitInfo2);
            VpData->GuestVmcb.StateSaveArea.Rip =
                VpData->GuestVmcb.ControlArea.NRip;
        }
    }

    //
    // 分发完成后、返回 Guest 前调用后置回调（服务侧快速收紧，如 CC 副本
    // 页在下一个 VMEXIT 立即重新武装）。仅初始化期注册，热路径无锁遍历。
    //
    KeMemoryBarrier();
    for (ULONG i = 0; i < g_PostExitCallbackCount; i++)
    {
        g_PostExitCallbacks[i](VpData);
    }

    if (oldIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(oldIrql);
    }

    if (guestContext.ExitVm != FALSE)
    {
        NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitCode == VMEXIT_CPUID);

        //
        // 设置 CPUID 返回结果：
        //   RBX = 返回地址（NRip）
        //   RCX = 要恢复的栈指针（Guest RSP）
        //   EDX:EAX = 每处理器数据地址
        //
        guestContext.VpRegs->Rax = reinterpret_cast<UINT64>(VpData) & MAXUINT32;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = reinterpret_cast<UINT64>(VpData) >> 32;

        //
        // 加载 Guest 状态（当前是 Host 状态）。
        //
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);

        //
        // 设置 GIF 但保持 IF=0（禁止中断，直到 SVM 关闭）。
        //
        _disable();
        __svm_stgi();

        //
        // 关闭 SVM 并恢复 Guest RFLAGS。
        //
        __writemsr(SVM_MSR_EFER, __readmsr(SVM_MSR_EFER) & ~EFER_SVME);
        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        goto Exit;
    }

    //
    // 把可能被修改的 Guest RAX 回写 VMCB（VMRUN 从 VMCB 加载 RAX）。
    //
    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

Exit:
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    return guestContext.ExitVm;
}
