/*!
    @file       NpSvm.h

    @brief      AMD SVM 硬件描述：SVM 常量、VMCB、NPT 页表、EVENTINJ、
                段描述符。纯硬件数据结构，不含任何策略。

    @note       本文件是 core 层与 AMD 架构相关的部分；若未来支持
                Intel VMX/EPT，将新增对应的 NpVmx.h，并让上层只依赖
                NpHv.h 的抽象接口。
 */
#pragma once

#include <basetsd.h>
#include <ntifs.h>

//
// ============================ SVM 常量 ============================
//

#define SVM_MSR_PERMISSIONS_MAP_SIZE    (PAGE_SIZE * 2)
#define SVM_MSR_VM_CR                   0xc0010114
#define SVM_MSR_VM_HSAVE_PA             0xc0010117
#define SVM_MSR_EFER                    0xc0000080
#define SVM_MSR_PAT                     0x00000277
#define SVM_MSR_LSTAR                   0xC0000082

#define SVM_VM_CR_SVMDIS                (1UL << 4)
#define SVM_VM_CR_LOCK                  (1UL << 0)

#define EFER_SVME                       (1UL << 12)

#define SVM_INTERCEPT_MISC1_CPUID       (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT    (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN       (1UL << 0)
#define SVM_INTERCEPT_MISC2_VMMCALL     (1UL << 1)

#define SVM_NP_ENABLE_NP_ENABLE         (1UL << 0)

// VMCB.TlbControl 取值（AMD APM Vol.2 Table 15-9）
//   00h = Do nothing
//   01h = Flush entire TLB (all ASIDs) —— 仅旧硬件语义，过度刷新
//   03h = Flush TLB entries for the current ASID —— 本框架使用
#define TLB_CONTROL_DO_NOTHING          (0x00)
#define TLB_CONTROL_FLUSH_ALL_ASID      (0x01)
#define TLB_CONTROL_FLUSH_ASID          (0x03)

//
// ============================ CPUID 常量 ============================
//

#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING      0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS   0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX 0x80000001
#define CPUID_SVM_FEATURES                                  0x8000000a
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS                   0x40000000
#define CPUID_HV_INTERFACE                                  0x40000001

#define CPUID_FN8000_0001_ECX_SVM                   (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                    (1UL << 0)

// 卸载后门：cpuid(eax = 0x41414141, ecx = 'NPTU') 且 CPL==0 时，
// Hypervisor 自卸载并返回到 cpuid 的下一条指令。
#define CPUID_UNLOAD_NPTHOOK      0x41414141
#define CPUID_UNLOAD_MAGIC        'NPTU'

// 内部检测（“本处理器是否已被虚拟化”）：cpuid(eax=0x41414141, ecx=0)
// 返回 EBX='NPHK'。用于虚拟化后 Guest 续跑路径的二次判断
// （隐身模式下不能用 0x40000000 厂商串判断）。
#define CPUID_HV_CHECK_MAGIC      0x00000000
#define CPUID_HV_CHECK_RETURN     'NPHK'

// 段选择子辅助
#define RPL_MASK                  3
#define DPL_SYSTEM                0

//
// ============================ VMMCALL 协议 (R0 + R3 hypercall dual-stack) ===
// R3 hypercall range: 0x4E505640..0x4E50564F (CPL3 allowed)
#define VMMCALL_HYPERCALL_BASE          0x4E505640
#define VMMCALL_HYPERCALL_PING          0x4E505640
#define VMMCALL_HYPERCALL_QUERY_STATUS  0x4E505641
#define VMMCALL_HYPERCALL_GET_DEVICE_NAME 0x4E505642
#define VMMCALL_HYPERCALL_DBG_HIDE          0x4E505643
#define VMMCALL_HYPERCALL_DBG_PROTECT       0x4E505644
#define VMMCALL_HYPERCALL_DBG_MODE          0x4E505645
#define VMMCALL_HYPERCALL_MAX           0x4E50564F
// ============================ VMMCALL 协议 ============================
//
// 跳板在 Guest 内执行，通过 VMMCALL 与 Hypervisor 通信。
// eax = 功能码；仅 CPL 0 允许。
#define VMMCALL_HOOK_DONE           0x00004e50  // 'NP'
#define VMMCALL_RESET_SHADOWS       0x00004e51  // 'NQ'
#define VMMCALL_BP_CONTINUE         0x00004e52  // 'NR'：继续被暂停的断点（rcx=bpId，0=全部）
#define VMMCALL_DRPROBE_SET         0x00004e53  // 'NS'：开启/关闭 DR 探测（rcx=0/1）
#define VMMCALL_SYSCALL_DISPATCH    0x00004e58  // 'NX'：LSTAR 跳板 syscall 命中（rdi=syscall#）

//
// ============================ VMEXIT 编码 ============================
//

#define VMEXIT_EXCEPTION_BP         0x0043
#define VMEXIT_EXCEPTION_DB         0x0041  // #DB（调试异常，单步用）
#define VMEXIT_CPUID                0x0072
#define VMEXIT_MSR                  0x007c
#define VMEXIT_VMRUN                0x0080
#define VMEXIT_VMMCALL              0x0081
#define VMEXIT_SHUTDOWN             0x007f
#define VMEXIT_NPF                  0x0400
#define VMEXIT_INVALID              -1

//
// ============================ DR 访问 VMEXIT 编码 ============================
//
// AMD SVM（APM Vol.2 Table 15-2 "SVM Intercept Exit Codes"）：
//   CR Read  = 0x000-0x00F（CR0-15）
//   CR Write = 0x010-0x01F
//   DR Read  = 0x020-0x027（DR0-7，每个 DR 独立编码）
//   DR Write = 0x030-0x037
//   Exception = 0x040+vector（#DB=0x41、#BP=0x43）
//
// DR 拦截位：VMCB.InterceptDrRead / InterceptDrWrite（16 位字段），
// bit n 对应 DRn（DR0-3=bit0-3、DR4=bit4、DR5=bit5、DR6=bit6、DR7=bit7）。
// x64 长模式下访问 DR4/5 无条件 #UD（与 CR4.DE 无关），无需拦截。
//

#define VMEXIT_DR0_READ         0x0020
#define VMEXIT_DR1_READ         0x0021
#define VMEXIT_DR2_READ         0x0022
#define VMEXIT_DR3_READ         0x0023
#define VMEXIT_DR4_READ         0x0024
#define VMEXIT_DR5_READ         0x0025
#define VMEXIT_DR6_READ         0x0026
#define VMEXIT_DR7_READ         0x0027
#define VMEXIT_DR0_WRITE        0x0030
#define VMEXIT_DR1_WRITE        0x0031
#define VMEXIT_DR2_WRITE        0x0032
#define VMEXIT_DR3_WRITE        0x0033
#define VMEXIT_DR4_WRITE        0x0034
#define VMEXIT_DR5_WRITE        0x0035
#define VMEXIT_DR6_WRITE        0x0036
#define VMEXIT_DR7_WRITE        0x0037

// 拦截 DR0-3 + DR6 + DR7 读写（不含 DR4/5）
#define SVM_INTERCEPT_DR_ALL    0xCF    // bit0-3 | bit6 | bit7

// NPF 错误码 (ExitInfo1) 位定义
#define NPF_ERROR_PRESENT           (1UL << 0)
#define NPF_ERROR_WRITE             (1UL << 1)
#define NPF_ERROR_USER              (1UL << 2)
#define NPF_ERROR_IFETCH            (1UL << 4)

//
// ============================ VMCB 结构 ============================
//

typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;             // +0x000
    UINT16 InterceptCrWrite;            // +0x002
    UINT16 InterceptDrRead;             // +0x004
    UINT16 InterceptDrWrite;            // +0x006
    UINT32 InterceptException;          // +0x008
    UINT32 InterceptMisc1;              // +0x00c
    UINT32 InterceptMisc2;              // +0x010
    UINT8 Reserved1[0x03c - 0x014];     // +0x014
    UINT16 PauseFilterThreshold;        // +0x03c
    UINT16 PauseFilterCount;            // +0x03e
    UINT64 IopmBasePa;                  // +0x040
    UINT64 MsrpmBasePa;                 // +0x048
    UINT64 TscOffset;                   // +0x050
    UINT32 GuestAsid;                   // +0x058
    UINT32 TlbControl;                  // +0x05c
    UINT64 VIntr;                       // +0x060
    UINT64 InterruptShadow;             // +0x068
    UINT64 ExitCode;                    // +0x070
    UINT64 ExitInfo1;                   // +0x078
    UINT64 ExitInfo2;                   // +0x080
    UINT64 ExitIntInfo;                 // +0x088
    UINT64 NpEnable;                    // +0x090
    UINT64 AvicApicBar;                 // +0x098
    UINT64 GuestPaOfGhcb;               // +0x0a0
    UINT64 EventInj;                    // +0x0a8
    UINT64 NCr3;                        // +0x0b0
    UINT64 LbrVirtualizationEnable;     // +0x0b8
    UINT64 VmcbClean;                   // +0x0c0
    UINT64 NRip;                        // +0x0c8
    UINT8 NumOfBytesFetched;            // +0x0d0
    UINT8 GuestInstructionBytes[15];    // +0x0d1
    UINT64 AvicApicBackingPagePointer;  // +0x0e0
    UINT64 Reserved2;                   // +0x0e8
    UINT64 AvicLogicalTablePointer;     // +0x0f0
    UINT64 AvicPhysicalTablePointer;    // +0x0f8
    UINT64 Reserved3;                   // +0x100
    UINT64 VmcbSaveStatePointer;        // +0x108
    UINT8 Reserved4[0x400 - 0x110];     // +0x110
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;
static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400,
              "VMCB_CONTROL_AREA Size Mismatch");

typedef struct _VMCB_STATE_SAVE_AREA
{
    UINT16 EsSelector;                  // +0x000
    UINT16 EsAttrib;                    // +0x002
    UINT32 EsLimit;                     // +0x004
    UINT64 EsBase;                      // +0x008
    UINT16 CsSelector;                  // +0x010
    UINT16 CsAttrib;                    // +0x012
    UINT32 CsLimit;                     // +0x014
    UINT64 CsBase;                      // +0x018
    UINT16 SsSelector;                  // +0x020
    UINT16 SsAttrib;                    // +0x022
    UINT32 SsLimit;                     // +0x024
    UINT64 SsBase;                      // +0x028
    UINT16 DsSelector;                  // +0x030
    UINT16 DsAttrib;                    // +0x032
    UINT32 DsLimit;                     // +0x034
    UINT64 DsBase;                      // +0x038
    UINT16 FsSelector;                  // +0x040
    UINT16 FsAttrib;                    // +0x042
    UINT32 FsLimit;                     // +0x044
    UINT64 FsBase;                      // +0x048
    UINT16 GsSelector;                  // +0x050
    UINT16 GsAttrib;                    // +0x052
    UINT32 GsLimit;                     // +0x054
    UINT64 GsBase;                      // +0x058
    UINT16 GdtrSelector;                // +0x060
    UINT16 GdtrAttrib;                  // +0x062
    UINT32 GdtrLimit;                   // +0x064
    UINT64 GdtrBase;                    // +0x068
    UINT16 LdtrSelector;                // +0x070
    UINT16 LdtrAttrib;                  // +0x072
    UINT32 LdtrLimit;                   // +0x074
    UINT64 LdtrBase;                    // +0x078
    UINT16 IdtrSelector;                // +0x080
    UINT16 IdtrAttrib;                  // +0x082
    UINT32 IdtrLimit;                   // +0x084
    UINT64 IdtrBase;                    // +0x088
    UINT16 TrSelector;                  // +0x090
    UINT16 TrAttrib;                    // +0x092
    UINT32 TrLimit;                     // +0x094
    UINT64 TrBase;                      // +0x098
    UINT8 Reserved1[0x0cb - 0x0a0];     // +0x0a0
    UINT8 Cpl;                          // +0x0cb
    UINT32 Reserved2;                   // +0x0cc
    UINT64 Efer;                        // +0x0d0
    UINT8 Reserved3[0x148 - 0x0d8];     // +0x0d8
    UINT64 Cr4;                         // +0x148
    UINT64 Cr3;                         // +0x150
    UINT64 Cr0;                         // +0x158
    UINT64 Dr7;                         // +0x160
    UINT64 Dr6;                         // +0x168
    UINT64 Rflags;                      // +0x170
    UINT64 Rip;                         // +0x178
    UINT8 Reserved4[0x1d8 - 0x180];     // +0x180
    UINT64 Rsp;                         // +0x1d8
    UINT8 Reserved5[0x1f8 - 0x1e0];     // +0x1e0
    UINT64 Rax;                         // +0x1f8
    UINT64 Star;                        // +0x200
    UINT64 LStar;                       // +0x208
    UINT64 CStar;                       // +0x210
    UINT64 SfMask;                      // +0x218
    UINT64 KernelGsBase;                // +0x220
    UINT64 SysenterCs;                  // +0x228
    UINT64 SysenterEsp;                 // +0x230
    UINT64 SysenterEip;                 // +0x238
    UINT64 Cr2;                         // +0x240
    UINT8 Reserved6[0x268 - 0x248];     // +0x248
    UINT64 GPat;                        // +0x268
    UINT64 DbgCtl;                      // +0x270
    UINT64 BrFrom;                      // +0x278
    UINT64 BrTo;                        // +0x280
    UINT64 LastExcepFrom;               // +0x288
    UINT64 LastExcepTo;                 // +0x290
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;
static_assert(sizeof(VMCB_STATE_SAVE_AREA) == 0x298,
              "VMCB_STATE_SAVE_AREA Size Mismatch");

typedef struct _VMCB
{
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UINT8 Reserved1[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;
static_assert(sizeof(VMCB) == 0x1000, "VMCB Size Mismatch");

typedef struct _EVENTINJ
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Vector : 8;          // [0:7]
            UINT64 Type : 3;            // [8:10]
            UINT64 ErrorCodeValid : 1;  // [11]
            UINT64 Reserved1 : 19;      // [12:30]
            UINT64 Valid : 1;           // [31]
            UINT64 ErrorCode : 32;      // [32:63]
        } Fields;
    };
} EVENTINJ, *PEVENTINJ;
static_assert(sizeof(EVENTINJ) == 8, "EVENTINJ Size Mismatch");

//
// ============================ NPT 页表结构 ============================
//
// NPT 页表项格式与 x64 普通页表一致（这是 NPT 相比 EPT 的友好之处）。
// 叶子项 bit7 = PAT；2MB 大页项（PDE）bit7 = PS。
//

typedef union _NPT_ENTRY
{
    UINT64 AsUInt64;
    struct
    {
        UINT64 Present : 1;         // [0]
        UINT64 Write : 1;           // [1]
        UINT64 User : 1;            // [2]
        UINT64 WriteThrough : 1;    // [3]
        UINT64 CacheDisable : 1;    // [4]
        UINT64 Accessed : 1;        // [5]
        UINT64 Dirty : 1;           // [6]
        UINT64 PatOrPs : 1;         // [7] 叶子4KB: PAT；叶子2MB: PS(大页)
        UINT64 Global : 1;          // [8]
        UINT64 Avl : 3;             // [9:11]
        UINT64 PageFrameNumber : 40;// [12:51]
        UINT64 Reserved : 11;       // [52:62]
        UINT64 NoExecute : 1;       // [63]
    } Fields;
} NPT_ENTRY, *PNPT_ENTRY;
static_assert(sizeof(NPT_ENTRY) == 8, "NPT_ENTRY Size Mismatch");

// 每 CPU 一棵完整的 NPT：PML4(1页) + PDPT(1页) + PD(512页)。
// 512 个 PDE × 2MB = 512GB 恒等映射（GPA == HPA）。
// 之所以不做全局共享，而是每 CPU 一棵：Hook 触发时每个核心的
// 页表处于不同状态（CPU A 在“执行视图”，CPU B 在“读/写视图”），
// 必须互相独立。上层共享是一个优化，暂不实现。

typedef struct _NPT_ROOT
{
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_ENTRY Pml4[512];      // +0x0000 (1页)
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_ENTRY Pdpt[512];      // +0x1000 (1页)
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_ENTRY Pd[512][512];   // +0x2000 (512页)
    // 大页拆分用 PT 页池（构建时清零，拆分时从位图取页）
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_ENTRY Pt[NPTHOOK_MAX_SPLIT_PT_PER_CPU][512];
    ULONG_PTR PtPhysical[NPTHOOK_MAX_SPLIT_PT_PER_CPU]; // 构建时填充（避免 VMEXIT 中调 MmGetPhysicalAddress）
    ULONG PtUsageBitmap[(NPTHOOK_MAX_SPLIT_PT_PER_CPU + 31) / 32];
} NPT_ROOT, *PNPT_ROOT;
// 注意：结构体成员按页对齐，sizeof 会被圆整到 PAGE_SIZE 的整数倍。
// 用区间断言（578~579 页）避免 MSVC 对复杂常量表达式求值的差异问题。
static_assert(sizeof(NPT_ROOT) >=
                  (1 + 1 + 512 + NPTHOOK_MAX_SPLIT_PT_PER_CPU) * PAGE_SIZE +
                  sizeof(ULONG_PTR) * NPTHOOK_MAX_SPLIT_PT_PER_CPU +
                  ((NPTHOOK_MAX_SPLIT_PT_PER_CPU + 31) / 32) * sizeof(ULONG),
              "NPT_ROOT too small");
static_assert(sizeof(NPT_ROOT) <
                  (1 + 1 + 512 + NPTHOOK_MAX_SPLIT_PT_PER_CPU + 2) * PAGE_SIZE,
              "NPT_ROOT too large");

//
// ============================ 段描述符 ============================
//

#include <pshpack1.h>
typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, *PDESCRIPTOR_TABLE_REGISTER;
static_assert(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10,
              "DESCRIPTOR_TABLE_REGISTER Size Mismatch");
#include <poppack.h>

typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow;        // [0:15]
            UINT16 BaseLow;         // [16:31]
            UINT32 BaseMiddle : 8;  // [32:39]
            UINT32 Type : 4;        // [40:43]
            UINT32 System : 1;      // [44]
            UINT32 Dpl : 2;         // [45:46]
            UINT32 Present : 1;     // [47]
            UINT32 LimitHigh : 4;   // [48:51]
            UINT32 Avl : 1;         // [52]
            UINT32 LongMode : 1;    // [53]
            UINT32 DefaultBit : 1;  // [54]
            UINT32 Granularity : 1; // [55]
            UINT32 BaseHigh : 8;    // [56:63]
        } Fields;
    };
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;        // [0:3]
            UINT16 System : 1;      // [4]
            UINT16 Dpl : 2;         // [5:6]
            UINT16 Present : 1;     // [7]
            UINT16 Avl : 1;         // [8]
            UINT16 LongMode : 1;    // [9]
            UINT16 DefaultBit : 1;  // [10]
            UINT16 Granularity : 1; // [11]
            UINT16 Reserved1 : 4;   // [12:15]
        } Fields;
    };
} SEGMENT_ATTRIBUTE, *PSEGMENT_ATTRIBUTE;
