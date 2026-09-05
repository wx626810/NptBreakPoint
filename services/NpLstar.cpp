/*!
    @file       NpLstar.cpp

    @brief      LSTAR 接管（P1/P2/P3）：
                - 跳板：逐 syscall 比对，miss 直接 jmp 原始 KiSystemCall64
                  （零 VMEXIT）；hit 走 vmmcall + Guest 内核分发器；
                - 分发器：伪附加（DAP/Remove/Wait/Continue）、QIP 分流、
                  RVM/WVM 分流、SCT/GCT/Suspend/Resume 转发；
                - RDMSR 0xC0000082 永远回显原始 KiSystemCall64（反作弊
                  读 LSTAR 永远干净）。

                跳板 hit 路径在 Guest 内做标准 syscall 栈切换（swapgs +
                KPCR 保存用户 RSP + 取内核栈），因此分发器以 PASSIVE_LEVEL
                运行在调用者线程上下文，可安全执行 KeWaitForSingleObject /
                ProbeForWrite 等操作（真实内核实现不执行）。
 */
#define POOL_NX_OPTIN   1
#include "NpConfig.h"
#include "NptHook.hpp"
#include "NpHv.h"
#include "NpLstar.h"
#include "NpSyscall.h"
#include "NpPseudoDbg.h"
#include "NpDebugHide.h"
#include "NpProcessHide.h"
#include "NpBreakPoint.h"
#include "NpAsm.h"
#include "NpLog.h"
#include "NpMemAccess.h"
#include <intrin.h>

#define KPCR_USER_RSP_OFF       0x10
#define KPCR_RSP_BASE_OFF       0x1A8
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

PVOID g_OrigLstar = nullptr;
PVOID g_Trampoline = nullptr;
static BOOLEAN g_Enabled = FALSE;
static BOOLEAN g_KptiActive = FALSE;
static BOOLEAN g_NoNrips = FALSE;       // CPU 不支持 NRIP 保存时禁用 LSTAR

// 槽位表/就绪标志在驱动 .data（跳板用 movabs 绝对寻址，无 disp32 限制）。
static ULONG g_TrampSlots[16];
static volatile BOOLEAN g_LstarReady = FALSE;
static BOOLEAN g_InSlack = FALSE;          // 跳板位于 nt .text CC slack
static UCHAR g_SlackBackup[0x300];          // 卸载时还原原 CC 字节

// 被拦截 syscall 号（NpLstarInitialize 时解析）。
static ULONG g_Sc_DAP = 0, g_Sc_Remove = 0, g_Sc_Wait = 0, g_Sc_Continue = 0;
static ULONG g_Sc_WaitEx = 0;
static ULONG g_Sc_QIP = 0, g_Sc_Suspend = 0, g_Sc_Resume = 0;
static ULONG g_Sc_GCT = 0, g_Sc_SCT = 0, g_Sc_RVM = 0, g_Sc_WVM = 0;
static ULONG g_Sc_QSI = 0;

// 原函数指针（转发用；解析失败为 nullptr）。
static PVOID g_OrigQip = nullptr;
static PVOID g_OrigRvm = nullptr;
static PVOID g_OrigWvm = nullptr;
static PVOID g_OrigGct = nullptr;
static PVOID g_OrigSct = nullptr;
static PVOID g_OrigSuspend = nullptr;
static PVOID g_OrigResume = nullptr;
static PVOID g_OrigQsi = nullptr;
// 系统调用号/原函数是否已解析完成（解析后 GUI 刷新不再触碰 ntdll/扫描）。
static BOOLEAN g_SyscallsResolved = FALSE;

//
// ============================ 跳板字节发射器 ============================
//

static void Emit8(PUCHAR *P, UCHAR V) { *(*P)++ = V; }
static void Emit32(PUCHAR *P, ULONG V) { *(ULONG *)*P = V; *P += 4; }
static void Emit64(PUCHAR *P, ULONG64 V) { *(ULONG64 *)*P = V; *P += 8; }
static void EmitBytes(PUCHAR *P, const UCHAR *B, ULONG N) { RtlCopyMemory(*P, B, N); *P += N; }

// 从真实 KiSystemCall64 复制栈切换序言（swapgs + 保存用户 RSP + 切内核栈）。
// 找不到标准三连时回退硬编码（KPCR 偏移 Win10/11 x64 稳定）。
static ULONG CopyLstarPreamble(PUCHAR Out)
{
    static const UCHAR kFallback[21] = {
        0x0F, 0x01, 0xF8,                                        // swapgs
        0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00,    // mov gs:[10h], rsp
        0x65, 0x48, 0x8B, 0x24, 0x25, 0xA8, 0x01, 0x00, 0x00,    // mov rsp, gs:[1A8h]
    };
    static const UCHAR kPat1[3] = { 0x0F, 0x01, 0xF8 };
    static const UCHAR kPat2[9] = { 0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00 };
    static const UCHAR kPat3[9] = { 0x65, 0x48, 0x8B, 0x24, 0x25, 0xA8, 0x01, 0x00, 0x00 };

    if (g_OrigLstar != nullptr)
    {
        PUCHAR src = (PUCHAR)g_OrigLstar;
        __try
        {
            if (memcmp(src, kPat1, sizeof(kPat1)) == 0 &&
                memcmp(src + 3, kPat2, sizeof(kPat2)) == 0 &&
                memcmp(src + 12, kPat3, sizeof(kPat3)) == 0)
            {
                RtlCopyMemory(Out, src, sizeof(kFallback));
                return sizeof(kFallback);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    RtlCopyMemory(Out, kFallback, sizeof(kFallback));
    return sizeof(kFallback);
}

//
// ============================ 跳板构建 ============================
//

static NTSTATUS BuildTrampolineTo(PVOID OutBuf, ULONG_PTR BaseVa)
{
    PUCHAR out = (PUCHAR)OutBuf;
    RtlZeroMemory(out, PAGE_SIZE);
    PUCHAR p = out;

    //
    // 入口先做标准 syscall 栈切换（swapgs / 保存用户栈 / 切内核栈）。
    // 之后所有 push/pop 都在内核栈上执行——syscall 入口仍是用户栈时
    // 访问用户栈会触发 SMAP #PF（Windows 默认开 SMAP），这是首取指
    // 即冻结的根因之一。
    //
    ULONG pre = CopyLstarPreamble(p);
    p += pre;

    // 14 个固定槽位（内核栈上）：
    //   push r8 / movabs r8, slots / cmp eax,[r8+off] / je hit（×14）/ pop r8
    const ULONG kSlots = 14;                    // 11 基础 + WaitEx + QSI + 余量
    ULONG chainStart = (ULONG)(p - out);
    ULONG chainBytes = 2 + 10 + kSlots * 10 + 2; // push+movabs + 14×(cmp4+je6) + pop
    ULONG missBytes = 9 + 3 + 14;               // mov rsp,gs:[10h] + swapgs + jmp[rip+0]+orig
    ULONG hit = chainStart + chainBytes + missBytes;

    Emit8(&p, 0x41); Emit8(&p, 0x50);           // push r8
    Emit8(&p, 0x49); Emit8(&p, 0xB8);           // movabs r8, &g_TrampSlots
    Emit64(&p, (ULONG64)(ULONG_PTR)&g_TrampSlots);
    for (ULONG i = 0; i < kSlots; i++)
    {
        Emit8(&p, 0x41); Emit8(&p, 0x3B); Emit8(&p, 0x40);
        Emit8(&p, (UCHAR)(i * 4));               // cmp eax, [r8+disp8]
        Emit8(&p, 0x0F); Emit8(&p, 0x84);       // je hit (near, rel32)
        LONG jeDisp = (LONG)hit - (LONG)((p - out) + 4);
        Emit32(&p, (ULONG)jeDisp);
    }
    Emit8(&p, 0x41); Emit8(&p, 0x58);           // pop r8

    // miss：还原用户栈 + 用户 GS，然后原样进入 KiSystemCall64。
    Emit8(&p, 0x65); Emit8(&p, 0x48); Emit8(&p, 0x8B);
    Emit8(&p, 0x24); Emit8(&p, 0x25); Emit32(&p, 0x10);          // mov rsp, gs:[10h]
    Emit8(&p, 0x0F); Emit8(&p, 0x01); Emit8(&p, 0xF8);          // swapgs
    Emit8(&p, 0xFF); Emit8(&p, 0x25);           // jmp qword ptr [rip+0]
    Emit32(&p, 0);
    Emit64(&p, (ULONG64)g_OrigLstar);

    // hit：pop r8（恢复 arg4）→ 就绪门闩 → 帧 → vmmcall → 分发 → 返回
    p = out + hit;
    Emit8(&p, 0x41); Emit8(&p, 0x58);           // pop r8（chain 里 push 的那个）

    Emit8(&p, 0x41); Emit8(&p, 0x50);           // push r8
    Emit8(&p, 0x49); Emit8(&p, 0xB8);           // movabs r8, &g_LstarReady
    Emit64(&p, (ULONG64)(ULONG_PTR)&g_LstarReady);
    Emit8(&p, 0x41); Emit8(&p, 0x80); Emit8(&p, 0x38); Emit8(&p, 0x00);  // cmp byte [r8],0
    Emit8(&p, 0x41); Emit8(&p, 0x58);           // pop r8
    Emit8(&p, 0x75);                            // jne +5
    Emit8(&p, 0x05);
    Emit8(&p, 0xE9);                            // jmp rel32 -> miss
    LONG missDisp = (LONG)(BaseVa + chainStart + chainBytes -
                           (BaseVa + (p - out) + 4));
    Emit32(&p, (ULONG)missDisp);

    // 帧整体 +0x20，避开调用分发器时主调方 0x20 字节 shadow space，
    // 防止保存的用户 RIP/RFLAGS 被 C 调用覆盖（sysretq 回错地址的根因）。
    static const UCHAR kSubRsp70[]  = { 0x48, 0x83, 0xEC, 0x70 };
    static const UCHAR kMovRsp20Rcx[] = { 0x48, 0x89, 0x4C, 0x24, 0x20 };
    static const UCHAR kMovRsp28R11[] = { 0x4C, 0x89, 0x5C, 0x24, 0x28 };
    static const UCHAR kMovRsp30R10[] = { 0x4C, 0x89, 0x54, 0x24, 0x30 };
    static const UCHAR kMovRsp38Rdx[] = { 0x48, 0x89, 0x54, 0x24, 0x38 };
    static const UCHAR kMovRsp40R8[]  = { 0x4C, 0x89, 0x44, 0x24, 0x40 };
    static const UCHAR kMovRsp48R9[]  = { 0x4C, 0x89, 0x4C, 0x24, 0x48 };
    static const UCHAR kMovRsp50Eax[] = { 0x89, 0x44, 0x24, 0x50 };
    static const UCHAR kMovEaxSc[]    = { 0xB8, 0x58, 0x4E, 0x00, 0x00 };
    static const UCHAR kVmmcall[]     = { 0x0F, 0x01, 0xD9 };
    static const UCHAR kMovRaxGs10[]  = { 0x65, 0x48, 0x8B, 0x04, 0x25,
                                          0x10, 0x00, 0x00, 0x00 };
    static const UCHAR kMovRsp58Rax[] = { 0x48, 0x89, 0x44, 0x24, 0x58 };
    static const UCHAR kMovEaxRsp50[] = { 0x8B, 0x44, 0x24, 0x50 };
    static const UCHAR kMovEcxRsp50[] = { 0x8B, 0x4C, 0x24, 0x50 };
    static const UCHAR kLeaRdxRsp20[] = { 0x48, 0x8D, 0x54, 0x24, 0x20 };
    static const UCHAR kMovRaxImm[]   = { 0x48, 0xB8 };
    static const UCHAR kCallRax[]     = { 0xFF, 0xD0 };
    static const UCHAR kMovR10Rsp58[] = { 0x4C, 0x8B, 0x54, 0x24, 0x58 };
    static const UCHAR kMovR11Rsp28[] = { 0x4C, 0x8B, 0x5C, 0x24, 0x28 };
    static const UCHAR kMovRcxRsp20[] = { 0x48, 0x8B, 0x4C, 0x24, 0x20 };
    static const UCHAR kAddRsp70[]    = { 0x48, 0x83, 0xC4, 0x70 };
    static const UCHAR kCli[]         = { 0xFA };
    static const UCHAR kSwapgs[]      = { 0x0F, 0x01, 0xF8 };
    static const UCHAR kMovRspR10[]   = { 0x4C, 0x89, 0xD4 };
    // 注意：0F 05 是 SYSCALL；SYSRET 返回 64 位用户态必须带 REX.W
    // （48 0F 07），裸 0F 07 会返回兼容模式。
    static const UCHAR kSysret[]      = { 0x48, 0x0F, 0x07 };

    // 建帧：sub rsp, 0x70（[rsp+0x00..0x18] 留给分发器 shadow space）
    EmitBytes(&p, kSubRsp70, sizeof(kSubRsp70));
    EmitBytes(&p, kMovRsp20Rcx, sizeof(kMovRsp20Rcx));
    EmitBytes(&p, kMovRsp28R11, sizeof(kMovRsp28R11));
    EmitBytes(&p, kMovRsp30R10, sizeof(kMovRsp30R10));
    EmitBytes(&p, kMovRsp38Rdx, sizeof(kMovRsp38Rdx));
    EmitBytes(&p, kMovRsp40R8, sizeof(kMovRsp40R8));
    EmitBytes(&p, kMovRsp48R9, sizeof(kMovRsp48R9));
    EmitBytes(&p, kMovRsp50Eax, sizeof(kMovRsp50Eax));
    // 清空 Reserved（透传标记位），避免残留栈值误触发透传。
    static const UCHAR kZeroReserved[] = { 0xC7, 0x44, 0x24, 0x54,
                                           0x00, 0x00, 0x00, 0x00 };
    EmitBytes(&p, kZeroReserved, sizeof(kZeroReserved));

    // 保存用户栈指针（gs:[10h] 是内核 GS 下的 KPCR.UserRsp），
    // sysretq 前恢复 rsp 必须用它；r10 入口保存的是第一参数，不能当栈用。
    EmitBytes(&p, kMovRaxGs10, sizeof(kMovRaxGs10));
    EmitBytes(&p, kMovRsp58Rax, sizeof(kMovRsp58Rax));
    EmitBytes(&p, kMovEaxRsp50, sizeof(kMovEaxRsp50));   // 恢复 eax=syscall#
    EmitBytes(&p, kMovEaxSc, sizeof(kMovEaxSc));
    EmitBytes(&p, kVmmcall, sizeof(kVmmcall));

    // syscall 入口时 SYSCALL 按 SFMASK 清掉了 IF，分发器要访问用户栈 /
    // 阻塞等待（KeWaitForSingleObject），必须先把中断打开；否则用户页
    // 缺页在 IF=0 下无法投递，直接 0xD1 DISABLED_INTERRUPT_FAULT。
    Emit8(&p, 0xFB);                            // sti
    // 真实 KiSystemCall64 在服务分发前会 stac（AC=1），SMAP 下内核
    // 直接访问用户页才被放行；跳板漏掉这一步是历史所有 0x50 的根因。
    Emit8(&p, 0x0F); Emit8(&p, 0x01); Emit8(&p, 0xCB);   // stac

    EmitBytes(&p, kMovEcxRsp50, sizeof(kMovEcxRsp50));
    EmitBytes(&p, kLeaRdxRsp20, sizeof(kLeaRdxRsp20));
    EmitBytes(&p, kMovRaxImm, sizeof(kMovRaxImm));
    Emit64(&p, (ULONG64)(ULONG_PTR)&NpLstarSyscallDispatch);
    EmitBytes(&p, kCallRax, sizeof(kCallRax));

    // 透传：分发器置位 Frame->Reserved 后，恢复用户寄存器并重新进入
    // 原始 KiSystemCall64，避免从自定义跳板帧调用真实 Nt*。
    static const UCHAR kCmpPt[] = { 0x81, 0x7C, 0x24, 0x54,
                                    0x53, 0x4C, 0x54, 0x50 };  // cmp [rsp+54], 'SLTP'
    EmitBytes(&p, kCmpPt, sizeof(kCmpPt));
    ULONG jnePos = (ULONG)(p - out);
    Emit8(&p, 0x75);                                // jne normal
    Emit8(&p, 0x00);                                // disp 占位

    static const UCHAR kPtEax[]  = { 0x8B, 0x44, 0x24, 0x50 };
    static const UCHAR kPtRcx[]  = { 0x48, 0x8B, 0x4C, 0x24, 0x20 };
    static const UCHAR kPtR11[]  = { 0x4C, 0x8B, 0x5C, 0x24, 0x28 };
    static const UCHAR kPtR10[]  = { 0x4C, 0x8B, 0x54, 0x24, 0x30 };
    static const UCHAR kPtRdx[]  = { 0x48, 0x8B, 0x54, 0x24, 0x38 };
    static const UCHAR kPtR8[]   = { 0x4C, 0x8B, 0x44, 0x24, 0x40 };
    static const UCHAR kPtR9[]   = { 0x4C, 0x8B, 0x4C, 0x24, 0x48 };
    static const UCHAR kPtRsp[]  = { 0x48, 0x8B, 0x64, 0x24, 0x58 };
    EmitBytes(&p, kPtEax, sizeof(kPtEax));
    EmitBytes(&p, kPtRcx, sizeof(kPtRcx));
    EmitBytes(&p, kPtR11, sizeof(kPtR11));
    EmitBytes(&p, kPtR10, sizeof(kPtR10));
    EmitBytes(&p, kPtRdx, sizeof(kPtRdx));
    EmitBytes(&p, kPtR8, sizeof(kPtR8));
    EmitBytes(&p, kPtR9, sizeof(kPtR9));
    EmitBytes(&p, kPtRsp, sizeof(kPtRsp));
    Emit8(&p, 0x0F); Emit8(&p, 0x01); Emit8(&p, 0xCA);   // clac
    Emit8(&p, kCli[0]);
    EmitBytes(&p, kSwapgs, sizeof(kSwapgs));
    Emit8(&p, 0xFF); Emit8(&p, 0x25);           // jmp [rip+0] -> orig
    Emit32(&p, 0);
    Emit64(&p, (ULONG64)g_OrigLstar);

    ULONG normalPos = (ULONG)(p - out);
    out[jnePos + 1] = (UCHAR)(normalPos - (jnePos + 2));

    EmitBytes(&p, kMovR10Rsp58, sizeof(kMovR10Rsp58));
    EmitBytes(&p, kMovR11Rsp28, sizeof(kMovR11Rsp28));
    EmitBytes(&p, kMovRcxRsp20, sizeof(kMovRcxRsp20));
    EmitBytes(&p, kAddRsp70, sizeof(kAddRsp70));
    Emit8(&p, 0x0F); Emit8(&p, 0x01); Emit8(&p, 0xCA);   // clac
    Emit8(&p, kCli[0]);
    EmitBytes(&p, kSwapgs, sizeof(kSwapgs));
    EmitBytes(&p, kMovRspR10, sizeof(kMovRspR10));
    EmitBytes(&p, kSysret, sizeof(kSysret));

    // 自检：第一个槽的 je 必须是 0F 84（防小端写出顺序回归）。
    // 槽 0 的 je 位于 chain 起点 + push r8(2) + movabs r8(10) + cmp(4)。
    const ULONG kChainPrefix = 2 + 10;
    const ULONG kSlotCmp = 4;
    const ULONG kSlot0Je = chainStart + kChainPrefix + kSlotCmp;
    if (out[kSlot0Je] != 0x0F || out[kSlot0Je + 1] != 0x84)
    {
        return STATUS_UNSUCCESSFUL;
    }
    // miss 开头（mov rsp,gs:[10h]）必须完好地位于 hit 之前。
    if (out[chainStart + chainBytes] != 0x65)
    {
        return STATUS_UNSUCCESSFUL;
    }
    // 预初始化阶段日志服务可能尚未就绪，用 DbgPrint。
    NpDebugPrint("[lstar] trampoline: %lu slots, chain=0x%x miss=0x%x "
                 "hit=0x%x len=0x%x orig=%p\n",
                 kSlots, chainStart, chainStart + chainBytes, hit,
                 (ULONG)(p - out), g_OrigLstar);
    return STATUS_SUCCESS;
}

//
// ============================ 生命周期 ============================
//

// 在页面内找连续 CC slack（对齐空洞）。
static ULONG_PTR FindCcSlack(PVOID PageVa, ULONG Need)
{
    PUCHAR p = (PUCHAR)PageVa;
    ULONG run = 0;
    ULONG_PTR start = 0;
    __try
    {
        for (ULONG i = 0; i < PAGE_SIZE; i++)
        {
            if (p[i] == 0xCC)
            {
                if (run == 0) start = (ULONG_PTR)PageVa + i;
                if (++run >= Need) return start;
            }
            else
            {
                run = 0;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

// 通过 MDL 把代码写入只读内核 .text（绕过只读 PTE）。
static NTSTATUS WriteKernelText(ULONG_PTR Dst, PVOID Src, ULONG Len)
{
    PMDL mdl = IoAllocateMdl((PVOID)Dst, Len, FALSE, FALSE, nullptr);
    if (mdl == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(mdl);
    PVOID map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached,
                                             nullptr, FALSE, HighPagePriority);
    if (map == nullptr)
    {
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(map, Src, Len);
    MmUnmapLockedPages(map, mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS NpLstarPreInitialize(void)
{
    // 虚拟化前：MSR 拦截未开启，直接读真实 LSTAR；并预建固定槽位跳板，
    // 虚拟化时每核在各自 VMCB 预置 LSTAR（无需运行时跨核同步）。
    g_OrigLstar = (PVOID)__readmsr(SVM_MSR_LSTAR);
    if (g_OrigLstar == nullptr) return STATUS_UNSUCCESSFUL;

    //
    // KPTI 探测：KiSystemCall64(Shadow) 序言里有
    //   cmp qword ptr gs:[disp32], 0
    // 该位置非零 = KPTI 启用 → syscall 入口仍在用户 CR3，跳板页不可达。
    //
    g_KptiActive = FALSE;
    PUCHAR src = (PUCHAR)g_OrigLstar;
    __try
    {
        for (ULONG i = 0; i + 12 <= 96; i++)
        {
            if (src[i] == 0x65 && src[i + 1] == 0x48 &&
                src[i + 2] == 0x83 && src[i + 3] == 0x3C &&
                src[i + 4] == 0x25 && src[i + 9] == 0x00)
            {
                LONG disp = *(PLONG)(src + i + 5);
                if (disp >= 0 && disp < 0x10000)
                {
                    g_KptiActive = (__readgsqword((ULONG_PTR)disp) != 0);
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    // APM Vol.2 15.7.1：NRIP 保存支持由 CPUID Fn8000_000A_EDX[NRIPS](bit3)
    // 指示；不支持则 vmmcall 后 NRip 不可用，LSTAR 路径无法恢复。
    {
        int regs[4];
        __cpuidex(regs, 0x8000000A, 0);
        g_NoNrips = ((regs[3] & (1 << 3)) == 0);
    }
    NpDebugPrint("[lstar] pre-init: KPTI %s\n",
                 g_KptiActive ? "ACTIVE (LSTAR path disabled)" : "off");
    NpDebugPrint("[lstar] pre-init: NRIPS %s\n",
                 g_NoNrips ? "UNSUPPORTED (LSTAR path disabled)" : "ok");
    if (g_NoNrips)
    {
        return STATUS_SUCCESS;          // 回退旧路径
    }

    if (g_KptiActive)
    {
        // KPTI 下 LSTAR 跳板不可行：不预置 LSTAR，上层回退旧 NpHook 路径。
        NpDebugPrint("[lstar] pre-init: KPTI active, skip LSTAR trampoline\n");
        return STATUS_SUCCESS;
    }

    //
    // 直接验证 EXECUTE 池在加载早期是否可执行：写入单字节 ret 并调用。
    // 若该池实际为 NX，调用会 #PF（蓝屏并给出探针地址），一锤定音。
    //
    {
        PVOID probe = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                      PAGE_SIZE, 'LstN');
        if (probe != nullptr)
        {
            *(PUCHAR)probe = 0xC3;              // ret
            NpDebugPrint("[lstar] exec-pool probe: call %p\n", probe);
            ((void(*)(void))probe)();
            NpDebugPrint("[lstar] exec-pool probe: OK (executable)\n");
            ExFreePoolWithTag(probe, 'LstN');
        }
        else
        {
            NpDebugPrint("[lstar] exec-pool probe: alloc failed\n");
        }
    }

    //
    // 报告 §2.1：LSTAR 别名应落在 nt .text 的 CC slack 内（与原 syscall
    // 入口同页 → 用户 CR3 必然映射该页，规避池页在 syscall 入口不可达）。
    //
    const ULONG kTrampNeed = 0x180;
    ULONG_PTR slack = FindCcSlack(
        (PVOID)((ULONG_PTR)g_OrigLstar & ~(ULONG_PTR)0xFFF), kTrampNeed);
    if (slack != 0)
    {
        PVOID tmp = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'LstN');
        if (tmp == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = BuildTrampolineTo(tmp, slack);
        if (NT_SUCCESS(status))
        {
            __try
            {
                RtlCopyMemory(g_SlackBackup, (PVOID)slack, kTrampNeed);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            status = WriteKernelText(slack, tmp, kTrampNeed);
        }
        ExFreePoolWithTag(tmp, 'LstN');
        if (!NT_SUCCESS(status)) return status;
        g_Trampoline = (PVOID)slack;
        g_InSlack = TRUE;
        NpDebugPrint("[lstar] pre-init: trampoline in nt .text CC slack "
                     "at %p\n", g_Trampoline);
    }
    else
    {
        // 无 slack：回退可执行池（报告允许的兜底）。
        g_Trampoline = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                       PAGE_SIZE, 'LstN');
        if (g_Trampoline == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = BuildTrampolineTo(g_Trampoline,
                                            (ULONG_PTR)g_Trampoline);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(g_Trampoline, 'LstN');
            g_Trampoline = nullptr;
            return status;
        }
        NpDebugPrint("[lstar] pre-init: no CC slack, fallback pool "
                     "trampoline\n");
    }

    for (ULONG i = 0; i < 16; i++)
        g_TrampSlots[i] = 0xFFFFFFFF;           // 空槽永不匹配
    g_LstarReady = FALSE;

    NpDebugPrint("[lstar] pre-init: trampoline=%p orig=%p (slots idle)\n",
                 g_Trampoline, g_OrigLstar);
    return STATUS_SUCCESS;
}

static VOID ResolveSyscalls(void)
{
    // syscall 号首次解析后缓存；后续刷新不再触碰 ntdll（GUI 线程
    // 卡死的根源就是刷新第一步读 ntdll）。
    if (g_Sc_DAP == 0) g_Sc_DAP = NpSyscallExtractNumber("NtDebugActiveProcess");
    if (g_Sc_Remove == 0) g_Sc_Remove = NpSyscallExtractNumber("NtRemoveProcessDebug");
    if (g_Sc_Wait == 0) g_Sc_Wait = NpSyscallExtractNumber("NtWaitForDebugEvent");
    if (g_Sc_WaitEx == 0) g_Sc_WaitEx = NpSyscallExtractNumber("NtWaitForDebugEventEx");
    if (g_Sc_Continue == 0) g_Sc_Continue = NpSyscallExtractNumber("NtDebugContinue");
    if (g_Sc_QIP == 0) g_Sc_QIP = NpSyscallExtractNumber("NtQueryInformationProcess");
    if (g_Sc_Suspend == 0) g_Sc_Suspend = NpSyscallExtractNumber("NtSuspendThread");
    if (g_Sc_Resume == 0) g_Sc_Resume = NpSyscallExtractNumber("NtResumeThread");
    if (g_Sc_GCT == 0) g_Sc_GCT = NpSyscallExtractNumber("NtGetContextThread");
    if (g_Sc_SCT == 0) g_Sc_SCT = NpSyscallExtractNumber("NtSetContextThread");
    if (g_Sc_RVM == 0) g_Sc_RVM = NpSyscallExtractNumber("NtReadVirtualMemory");
    if (g_Sc_WVM == 0) g_Sc_WVM = NpSyscallExtractNumber("NtWriteVirtualMemory");
    if (g_Sc_QSI == 0) g_Sc_QSI = NpSyscallExtractNumber("NtQuerySystemInformation");

    // 解析成功即缓存；后续刷新只补缺，避免重复慢扫描/读 ntdll。
    if (g_OrigQip == nullptr)
        g_OrigQip = NpSyscallResolveRoutineEx("NtQueryInformationProcess", g_Sc_QIP, nullptr);
    if (g_OrigRvm == nullptr)
        g_OrigRvm = NpSyscallResolveRoutineEx("NtReadVirtualMemory", g_Sc_RVM, nullptr);
    if (g_OrigWvm == nullptr)
        g_OrigWvm = NpSyscallResolveRoutineEx("NtWriteVirtualMemory", g_Sc_WVM, nullptr);
    if (g_OrigGct == nullptr)
        g_OrigGct = NpSyscallResolveRoutineEx("NtGetContextThread", g_Sc_GCT, nullptr);
    if (g_OrigSct == nullptr)
        g_OrigSct = NpSyscallResolveRoutineEx("NtSetContextThread", g_Sc_SCT, nullptr);
    if (g_OrigSuspend == nullptr)
        g_OrigSuspend = NpSyscallResolveRoutineEx("NtSuspendThread", g_Sc_Suspend, nullptr);
    if (g_OrigResume == nullptr)
        g_OrigResume = NpSyscallResolveRoutineEx("NtResumeThread", g_Sc_Resume, nullptr);
    if (g_OrigQsi == nullptr)
        g_OrigQsi = NpSyscallResolveRoutineEx("NtQuerySystemInformation", g_Sc_QSI, nullptr);

    NpHvLogPrint("[lstar] orig QIP=%p RVM=%p WVM=%p GCT=%p SCT=%p "
                 "Sus=%p Res=%p QSI=%p\n",
                 g_OrigQip, g_OrigRvm, g_OrigWvm, g_OrigGct, g_OrigSct,
                 g_OrigSuspend, g_OrigResume, g_OrigQsi);
    g_SyscallsResolved = TRUE;
}

static VOID NpLstarResolveInUserCtx(VOID *Context)
{
    UNREFERENCED_PARAMETER(Context);
    NpSyscallRefreshIntercepts();
    ResolveSyscalls();
}

// 驱动加载期：附着任意用户进程完成 syscall 号 + 原函数解析并缓存，
// 之后 GUI 的刷新只重建槽位，绝不扫描镜像/读 ntdll。
static VOID NpLstarResolveAll(VOID)
{
    if (NpSyscallRunInUserContext(NpLstarResolveInUserCtx, nullptr))
    {
        NpDebugPrint("[lstar] resolve-all done in user context\n");
    }
}

extern "C" NTSTATUS NpLstarInitialize(void)
{
    if (g_Enabled) return STATUS_SUCCESS;

    if (g_KptiActive)
    {
        NpHvLogPrint("[lstar] KPTI active: LSTAR interception disabled\n");
        return STATUS_NOT_SUPPORTED;
    }
    if (g_Trampoline == nullptr) return STATUS_NOT_SUPPORTED;

    NpHvRegisterVmExitHandler(VMEXIT_VMMCALL, NpLstarHandleVmmcall);
    g_Enabled = TRUE;
    // 驱动加载期附着用户进程完成 syscall 号/原函数解析并缓存，
    // GUI 刷新不再碰 ntdll、不再做慢扫描。
    NpLstarResolveAll();
    NpHvLogPrint("[lstar] initialized: tramp=%p (LSTAR set per-CPU at "
                 "virtualize)\n", g_Trampoline);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS NpLstarRefresh(void)
{
    if (g_OrigLstar == nullptr) return STATUS_UNSUCCESSFUL;
    if (g_KptiActive) return STATUS_NOT_SUPPORTED;
    if (g_Trampoline == nullptr) return STATUS_NOT_SUPPORTED;
    NpDebugPrint("[lstar] refresh: begin pid=%lu\n",
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

    // 用户进程上下文：重新解析 syscall 号（含 prochide 动态加入的 QSI）。
    NpSyscallRefreshIntercepts();
    NpDebugPrint("[lstar] refresh: after intercepts\n");
    if (!g_SyscallsResolved || g_Sc_QSI==0 || g_Sc_QIP==0) ResolveSyscalls();
    NpDebugPrint("[lstar] refresh: after resolve\n");
    NpHvLogPrint("[lstar] sc DAP=%lu Wait=%lu QIP=%lu QSI=%lu RVM=%lu WVM=%lu "
                 "SCT=%lu\n",
                 g_Sc_DAP, g_Sc_Wait, g_Sc_QIP, g_Sc_QSI,
                 g_Sc_RVM, g_Sc_WVM, g_Sc_SCT);

    //
    // 只更新固定槽位数据，不动 LSTAR（LSTAR 在虚拟化时已预置）。
    //
    ULONG src[16];
    ULONG srcCount = 0;
    NTSTATUS st = NpSyscallCopyIntercepts(src, 16, &srcCount);
    if (!NT_SUCCESS(st)) return st;

    //
    // 基础拦截表全部武装：受保护目标由分发器伪造/处理，其余调用由跳板
    // 透传回原始 KiSystemCall64，不再依赖 g_Orig* 转发指针。
    //
    ULONG count = 0;
    for (ULONG i = 0; i < srcCount && count < 16; i++)
        g_TrampSlots[count++] = src[i];
    for (ULONG i = count; i < 16; i++)
        g_TrampSlots[i] = 0xFFFFFFFF;
    KeMemoryBarrier();
    g_LstarReady = TRUE;                        // 表数据就绪后才放行命中
    NpDebugPrint("[lstar] refresh: slots armed=%lu\n", count);
    NpHvLogPrint("[lstar] refreshed slots: %lu intercepts armed\n", count);
    return STATUS_SUCCESS;
}

extern "C" void NpLstarDisableForUnload(void)
{
    // Unload early gate: stop accepting new hits, keep trampoline mapped until Devirtualize.
    g_LstarReady = FALSE;
    KeMemoryBarrier();
}

extern "C" void NpLstarTeardown(void)
{
    if (g_OrigLstar != nullptr)
    {
        __writemsr(SVM_MSR_LSTAR, (ULONG64)g_OrigLstar);
    }
    if (g_InSlack && g_Trampoline != nullptr)
    {
        // 还原 nt .text CC slack 原字节。
        WriteKernelText((ULONG_PTR)g_Trampoline, g_SlackBackup,
                        (ULONG)sizeof(g_SlackBackup));
        g_InSlack = FALSE;
    }
    else if (g_Trampoline != nullptr)
    {
        ExFreePoolWithTag(g_Trampoline, 'LstN');
    }
    g_Trampoline = nullptr;
    g_Enabled = FALSE;
    for (ULONG i = 0; i < 16; i++)
        g_TrampSlots[i] = 0xFFFFFFFF;
    g_LstarReady = FALSE;
}

extern "C" BOOLEAN NpLstarHandleMsr(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx, ULONG Msr, BOOLEAN IsWrite)
{
    UNREFERENCED_PARAMETER(VpData);
    if (Msr != SVM_MSR_LSTAR) return FALSE;

    if (!IsWrite)
    {
        // 反作弊 RDMSR：永远看到真实 KiSystemCall64（跳板别名隐身）。
        ULONG64 orig = (ULONG64)(ULONG_PTR)g_OrigLstar;
        Ctx->VpRegs->Rax = (ULONG64)(ULONG)orig;
        Ctx->VpRegs->Rdx = orig >> 32;
        return TRUE;
    }

    // Guest（含驱动自身）写 LSTAR：仅允许驱动自己的跳板/原值回写，
    // 其余写入拒绝（防其它内核组件劫持 syscall 入口）。
    //
    // 注意：不能在这里 __writemsr 物理 MSR——SVM 的 vmload 在每次 VMRUN
    // 前会把 VMCB StateSaveArea 里的 STAR/LSTAR/CSTAR/SFMASK 重新加载进
    // MSR，写物理 MSR 会被下一轮覆盖。只改当前 CPU 的 VMCB.LStar。
    // （正常安装路径不再走 WRMSR：LSTAR 在虚拟化时按核预置。）
    ULONG64 value = (ULONG64)(ULONG)Ctx->VpRegs->Rax |
                    ((ULONG64)(ULONG)Ctx->VpRegs->Rdx << 32);
    if (value == (ULONG64)(ULONG_PTR)g_Trampoline ||
        value == (ULONG64)(ULONG_PTR)g_OrigLstar)
    {
        VpData->GuestVmcb.StateSaveArea.LStar = value;
    }
    return TRUE;
}

extern "C" PVOID NpLstarGetOriginalKiSystemCall64(void) { return g_OrigLstar; }
extern "C" ULONG_PTR NpLstarGetTrampolineVa(void) { return (ULONG_PTR)g_Trampoline; }
extern "C" BOOLEAN NpLstarIsEnabled(void)
{
    return g_Enabled && !g_KptiActive && !g_NoNrips;
}
extern "C" BOOLEAN NpLstarIsKptiActive(void) { return g_KptiActive; }
extern "C" ULONG NpLstarGetInterceptCount(void)
{
    ULONG n = 0;
    const ULONG scs[] = {
        g_Sc_DAP, g_Sc_Remove, g_Sc_Wait, g_Sc_Continue, g_Sc_QIP,
        g_Sc_Suspend, g_Sc_Resume, g_Sc_GCT, g_Sc_SCT, g_Sc_RVM, g_Sc_WVM,
        g_Sc_WaitEx,
    };
    for (ULONG i = 0; i < ARRAYSIZE(scs); i++) if (scs[i] != 0) n++;
    if (g_Sc_QSI != 0 && NpSyscallIsIntercepted(g_Sc_QSI)) n++;
    return n;
}

extern "C" BOOLEAN NpLstarHandleVmmcall(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_CONTEXT Ctx)
{
    ULONG code = (ULONG)(Ctx->VpRegs->Rax & 0xFFFFFFFF);
    if (VpData->GuestVmcb.StateSaveArea.Cpl != 0)
    {
        return FALSE;       // 用户态 vmmcall 交给内置逻辑 #GP
    }
    if (code != VMMCALL_SYSCALL_DISPATCH)
    {
        return FALSE;
    }
    static volatile ULONG s_scDiag = 0;
    if (InterlockedIncrement((volatile LONG *)&s_scDiag) <= 8)
    {
        // 跳板帧在 Guest 内核栈 [rsp+0x50] 保存了 syscall 号。
        // 注意：PUSHAQ 的 VpRegs->Rsp 是占位符，必须用 VMCB 保存的
        // Guest RSP（#VMEXIT 时硬件回写当前 Guest RSP）。
        ULONG_PTR guestRsp = VpData->GuestVmcb.StateSaveArea.Rsp;
        ULONG sc = 0;
        if (guestRsp >= 0xFFFF800000000000ULL &&
            guestRsp < 0xFFFFFFFFFF000000ULL &&
            MmIsAddressValid((PVOID)guestRsp) &&
            MmIsAddressValid((PVOID)(guestRsp + 0x50)))
        {
            sc = *(volatile ULONG *)(guestRsp + 0x50);
        }
        NpHvLogPrint("[lstar] vmmcall SYSCALL cpu=%u sc=%lu\n",
                     VpData->CpuIndex, sc);
    }
    // 跳板已把现场打包到内核栈帧，VMEXIT 只做一次通行确认，
    // 恢复后继续执行分发器（阻塞语义在 Guest 分发器内完成）。
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
    return TRUE;
}

//
// ============================ 用户内存辅助 ============================
//

// 从 gs:[10h]（KPCR 保存的用户 RSP）读取栈上第 5 参数指针。
static BOOLEAN LstarReadStackArg(ULONG_PTR *Out)
{
    ULONG_PTR stack = __readgsqword(KPCR_USER_RSP_OFF);
    if (stack == 0) return FALSE;
    // x64 调用约定：syscall 时 [rsp] 是调用者返回地址，第 5 参数在
    // userRsp+0x28（4×8 影子区之后）。
    ULONG_PTR arg = stack + 0x28;
    // 用 Guest 页表物理直读取第 5 参数，不经过虚拟地址解引用，
    // 天然规避 SMAP/KPTI/缺页投递问题（调用者栈页驻留物理内存）。
    ULONG bytes = 0;
    NTSTATUS st = NpMemAccessRead(
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), arg, Out,
        sizeof(ULONG_PTR), &bytes);
    return NT_SUCCESS(st) && bytes == sizeof(ULONG_PTR);
}

//
// ============================ 分发器 ============================
//

static ULONG LstarTargetPidFromHandle(HANDLE ProcessHandle)
{
    PEPROCESS process = nullptr;
    NTSTATUS st = ObReferenceObjectByHandle(ProcessHandle,
                                            PROCESS_QUERY_INFORMATION,
                                            *PsProcessType,
                                            KernelMode,
                                            (PVOID *)&process,
                                            nullptr);
    if (!NT_SUCCESS(st) || process == nullptr) return 0;
    ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(process);
    ObDereferenceObject(process);
    return pid;
}

// 置位透传标记：跳板会恢复用户寄存器并重新进入原始 KiSystemCall64，
// 不调用真实 Nt*（自定义跳板帧里调用真实 syscall 处理函数会破坏
// 调用上下文，导致 svchost/Explorer 崩溃或卡顿）。
static NTSTATUS LstarPassThrough(PLSTAR_SYSCALL_FRAME F)
{
    F->Reserved = NPHV_LSTAR_PASSTHROUGH;
    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS LstarHandleDebugActiveProcess(PLSTAR_SYSCALL_FRAME F)
{
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    if (target == 0 || target == 4) return STATUS_INVALID_CID;
    ULONG debugger = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    NpHvLogPrint("[dbg] DAP intercepted: tgt=%lu dbg=%lu\n",
                 target, debugger);

    // Real-attach mode: protect the target, register the debugger,
    // then pass through to the real NtDebugActiveProcess so a real
    // DebugPort is created and x64dbg receives real debug events.
    if (NpDebugHideGetMode() == NPHV_DEBUG_MODE_WHITELIST &&
        !NpDebugHideIsProtected(target))
    {
        NpDebugHideProtectProcess(target, TRUE);
    }
    NpDebugHideNoteDebugger(target, debugger);
    NpProcessHideAddPid(debugger);
    NpBreakPointSetDrProbe(TRUE);

    //
    // 真实附加前装 PEB 影子：内核在 DAP 里写 BeingDebugged 时写陷阱命中，
    // #DB 同步影子并清字段，Guest/调试器读到的 PEB 恒干净。若 DAP 最终
    // 失败，影子保持 PEB 干净也无副作用（目标仍在受保护集）。
    //
    {
        PEPROCESS tproc = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(target),
                                                  &tproc)) &&
            tproc != nullptr)
        {
            ULONG monId = 0;
            NTSTATUS mst = NpBreakPointInstallPebShadow(tproc, &monId);
            if (mst != STATUS_ALREADY_REGISTERED && !NT_SUCCESS(mst))
            {
                NpHvLogPrint("[dbghide] peb shadow install failed "
                             "pid=%lu status=0x%08x\n", target, mst);
            }
            ObDereferenceObject(tproc);
        }
    }

    NpHvLogPrint("[dbg] real attach tgt=%lu dbg=%lu (passthrough)\n",
                 target, debugger);
    return LstarPassThrough(F);
}

static NTSTATUS LstarHandleRemoveProcessDebug(PLSTAR_SYSCALL_FRAME F)
{
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    if (target == 0) return STATUS_INVALID_CID;
    ULONG debugger = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    NpProcessHideRemovePid(debugger);
    // Pseudo session -> pseudo detach; otherwise pass through to real RemoveProcessDebug.
    if (NpPseudoDbgIsSessionTarget(target, debugger))
    {
        return NpPseudoDbgDetachByTarget(target, debugger);
    }
    return LstarPassThrough(F);
}

static NTSTATUS LstarHandleWaitForDebugEvent(PLSTAR_SYSCALL_FRAME F)
{
    static volatile LONG s_waitHit = 0;
    if (InterlockedIncrement(&s_waitHit) <= 32)
    {
        NpHvLogPrint("[pseudo] wait syscall hit pid=%lu tid=%lu arg1=%p sc=%lu\n",
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                     (ULONG)(ULONG_PTR)PsGetCurrentThreadId(),
                     (PVOID)F->Arg1, F->SyscallNumber);
    }
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    if (target == 0)
    {
        NpPseudoDbgFindByDebugger(
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), &target, nullptr);
    }
    NpHvLogPrint("[pseudo] wait resolve target=%lu arg4=%p alertable=%u\n",
                 target, (PVOID)F->Arg4, (ULONG)(F->Arg2 != 0));
    if (target == 0)
    {
        // No pseudo session -> pass through to real NtWaitForDebugEvent (real attach).
        NpHvLogPrint("[dbg] wait passthrough pid=%lu\n",
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        return LstarPassThrough(F);
    }
    ULONG debugger = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    BOOLEAN alertable = (F->Arg2 != 0);
    ULONG eventSize = 0;
    PLARGE_INTEGER timeout = nullptr;
    LARGE_INTEGER localTimeout;

    // NtWaitForDebugEventEx（Win10 20H1±）第五参数为 DebugEventSize。
    if (F->SyscallNumber == g_Sc_WaitEx)
    {
        ULONG_PTR arg5 = 0;
        if (LstarReadStackArg(&arg5))
            eventSize = (ULONG)arg5;
    }

    if (F->Arg3 != 0)
    {
        if (!NT_SUCCESS(NpMemAccessCopyFromUser(F->Arg3, &localTimeout,
                                                sizeof(localTimeout))))
        {
            NpHvLogPrint("[pseudo] wait: timeout copy failed pid=%lu arg3=%p\n",
                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                         (PVOID)F->Arg3);
            return STATUS_ACCESS_VIOLATION;
        }
        timeout = &localTimeout;
    }

    if (F->Arg4 == 0)
    {
        NpHvLogPrint("[pseudo] wait: arg4 null pid=%lu\n",
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        return STATUS_INVALID_PARAMETER;
    }
    return NpPseudoDbgWaitEvent(target, debugger, alertable, timeout,
                                (PVOID)F->Arg4, eventSize);
}

static NTSTATUS LstarHandleDebugContinue(PLSTAR_SYSCALL_FRAME F)
{
    static volatile LONG s_contHit = 0;
    if (InterlockedIncrement(&s_contHit) <= 32)
    {
        NpHvLogPrint("[pseudo] continue syscall hit pid=%lu tid=%lu arg1=%p sc=%lu\n",
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                     (ULONG)(ULONG_PTR)PsGetCurrentThreadId(),
                     (PVOID)F->Arg1, F->SyscallNumber);
    }
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    if (target == 0)
        NpPseudoDbgFindByDebugger(
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), &target, nullptr);
    if (InterlockedCompareExchange(&s_contHit, 0, 0) <= 32)
    {
        NpHvLogPrint("[pseudo] continue resolve tgt=%lu pid=%lu tid=%lu\n",
                     target, (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                     (ULONG)(ULONG_PTR)PsGetCurrentThreadId());
    }
    //
    // 清扫僵尸断点：调试器已删除、但驱动侧残留的断点。必须在
    // NpPseudoDbgContinue 之前——此时调试器的 step-over 动作（若有）已经
    // 发生，判据才准确。
    //
    // 真实附加（passthrough）模式下 pseudo 会话不存在，target 解析恒为 0，
    // 此时按"不过滤进程"清扫（TargetPid=0 语义，见 NpBreakPoint.cpp）——
    // 否则清扫永远不触发，continue 后删除的断点仍然残留。
    //
    NpBreakPointReapZombieOnContinue(target);

    if (target == 0) return LstarPassThrough(F);

    return NpPseudoDbgContinue(target,
                               (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                               (ULONG)F->Arg3);
}

static NTSTATUS LstarHandleQueryInformationProcess(PLSTAR_SYSCALL_FRAME F)
{
    ULONG infoClass = (ULONG)F->Arg2;
    ULONG length = (ULONG)F->Arg4;
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // 分流：伪会话目标（调试器/AC/目标自读）与受保护集 → 干净值。
    if (target != 0 &&
        (NpPseudoDbgIsSessionTarget(target, caller) ||
         NpDebugHideIsProtected(target)))
    {
        ULONG_PTR status = 0;
        BOOLEAN handled = NpDebugHideQueryProcessInfoSplit(
            (HANDLE)F->Arg1, infoClass, (PVOID)F->Arg3, length, &status);
        if (handled)
        {
            return (NTSTATUS)status;
        }
    }

    return LstarPassThrough(F);
}

static NTSTATUS LstarHandleReadVirtualMemory(PLSTAR_SYSCALL_FRAME F)
{
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    SIZE_T bytes = 0;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    BOOLEAN handled = NpDebugHideReadVirtualMemorySplit(
        (HANDLE)F->Arg1, (PVOID)F->Arg2, (PVOID)F->Arg3, (SIZE_T)F->Arg4,
        NpPseudoDbgIsSessionTarget(target, caller), &bytes, &st);
    if (handled)
    {
        // 回填 NumberOfBytesRead（栈上第五参数）。
        ULONG_PTR retPtr = 0;
        if (LstarReadStackArg(&retPtr))
        {
            if (retPtr != 0)
            {
                NpMemAccessCopyToUser(retPtr, &bytes, (ULONG)sizeof(SIZE_T));
            }
        }
        return st;
    }
    return LstarPassThrough(F);
}

static NTSTATUS LstarHandleWriteVirtualMemory(PLSTAR_SYSCALL_FRAME F)
{
    ULONG target = LstarTargetPidFromHandle((HANDLE)F->Arg1);
    ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    SIZE_T bytes = 0;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    BOOLEAN handled = NpDebugHideWriteVirtualMemorySplit(
        (HANDLE)F->Arg1, (PVOID)F->Arg2, (PVOID)F->Arg3, (SIZE_T)F->Arg4,
        NpPseudoDbgIsSessionTarget(target, caller), &bytes, &st);
    if (handled) return st;
    return LstarPassThrough(F);
}

static NTSTATUS LstarForwardThreadCall(ULONG SyscallNumber, PLSTAR_SYSCALL_FRAME F)
{
    UNREFERENCED_PARAMETER(SyscallNumber);
    return LstarPassThrough(F);
}

extern "C" NTSTATUS NpLstarSyscallDispatch(ULONG SyscallNumber, PLSTAR_SYSCALL_FRAME Frame)
{
    // Guest 上下文（PASSIVE）：DbgPrint 安全，KD 实时可见。
    static volatile ULONG s_dispDiag = 0;
    ULONG diag = InterlockedIncrement((volatile LONG *)&s_dispDiag);
    if (diag <= 64)
    {
        NpDebugPrint("[lstar] dispatch sc=%lu pid=%lu n=%lu\n",
                     SyscallNumber,
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), diag);
    }

    if (g_Sc_DAP != 0 && SyscallNumber == g_Sc_DAP)
        return LstarHandleDebugActiveProcess(Frame);
    if (g_Sc_Remove != 0 && SyscallNumber == g_Sc_Remove)
        return LstarHandleRemoveProcessDebug(Frame);
    if ((g_Sc_Wait != 0 && SyscallNumber == g_Sc_Wait) ||
        (g_Sc_WaitEx != 0 && SyscallNumber == g_Sc_WaitEx))
        return LstarHandleWaitForDebugEvent(Frame);
    if (g_Sc_Continue != 0 && SyscallNumber == g_Sc_Continue)
        return LstarHandleDebugContinue(Frame);
    if (g_Sc_QIP != 0 && SyscallNumber == g_Sc_QIP)
        return LstarHandleQueryInformationProcess(Frame);
    if (g_Sc_QSI != 0 && SyscallNumber == g_Sc_QSI)
    {
        // SelfHide first (SystemModuleInformation filtering)
        extern BOOLEAN NpSelfHideHandleQsiLstar(ULONG, PVOID, ULONG, PULONG, NTSTATUS*);
        ULONG_PTR status = 0; NTSTATUS selfSt=0;
        if (NpSelfHideHandleQsiLstar((ULONG)Frame->Arg1, (PVOID)Frame->Arg2, (ULONG)Frame->Arg3, (PULONG)Frame->Arg4, &selfSt)) {
            return selfSt;
        }
        if (g_OrigQsi != nullptr &&
            NpProcessHideHandleQsiSplit(Frame->Arg1, Frame->Arg2, Frame->Arg3,
                                        Frame->Arg4, &status))
        {
            return (NTSTATUS)status;
        }
        return LstarPassThrough(Frame);
    }
    if (g_Sc_RVM != 0 && SyscallNumber == g_Sc_RVM)
        return LstarHandleReadVirtualMemory(Frame);
    if (g_Sc_WVM != 0 && SyscallNumber == g_Sc_WVM)
        return LstarHandleWriteVirtualMemory(Frame);
    if (SyscallNumber == g_Sc_GCT || SyscallNumber == g_Sc_SCT ||
        SyscallNumber == g_Sc_Suspend || SyscallNumber == g_Sc_Resume)
    {
        return LstarForwardThreadCall(SyscallNumber, Frame);
    }
    if (diag <= 64)
    {
        NpHvLogPrint("[lstar] dispatch: unhandled syscall #%lu pid=%lu\n",
                     SyscallNumber,
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    }
    return LstarPassThrough(Frame);
}
