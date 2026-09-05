/*!
    @file       NpReloc.cpp

    @brief      克隆页重定位器实现（见 NpReloc.h）。

    @details    重写规则（仅作用于调用方提供的【代码区间】内；区间外
                的跳转表/对齐/填充数据原样复制，绝不解码）：
                - E8 call rel32（目标出块）→ mov r11,imm64; call r11（12B）
                - E9/EB jmp（出块）→ mov r11,imm64; jmp r11（12B）
                - 0F 8x / 70-7F jcc（出块）→ 反向短跳(2B) + r11 跳板(14B)
                - 块内 rel8 分支统一扩为 rel32（布局变化后防溢出）
                - lea r,[rip]（出块）→ mov r,imm64（10B，地址语义等价）
                - 其余 RIP 相对内存引用（出块）→
                    mov <死寄存器>,imm64; <原指令以 [r] 重编码>
                  （死寄存器由前向控制流存活分析选取；无可用则失败）
                - nop [rip] → nop（1B）
                - 块内相对目标：保持相对并重算位移（布局变化后）

                存活分析：从重写点沿控制流前向扫描（深度/范围受限），
                候选寄存器在所有可达路径上先写后读 → 可用作暂存。
                任何不确定性一律判活（保守）。

                失败（含类别与偏移）写入 Result->FailKind/FailOff，
                调用方必须拒绝安装该 Hook（宁可失败不可错误）。
  */
#include "NpReloc.h"
#include "NpDisasm.hpp"

#if defined(NPTHOOK_KERNEL_BUILD)
#define POOL_NX_OPTIN 1
#include <ntifs.h>
// 内核态：工作区必须堆分配（栈上 256KB 会让 _chkstk 探测越过线程栈底
// → PAGE_FAULT_IN_NONPAGED_AREA 0x50，实测蓝屏）。
#define NP_RELOC_ALLOC(Sz) ExAllocatePool2(POOL_FLAG_NON_PAGED, (Sz), 'lcRN')
#define NP_RELOC_FREE(P)    ExFreePoolWithTag((P), 'lcRN')
#else
#include <cstdlib>
#define NP_RELOC_ALLOC(Sz) std::malloc(Sz)
#define NP_RELOC_FREE(P)    std::free(P)
#endif

#ifdef NP_RELOC_DEBUG
#include <cstdio>
#define RELOC_DBG(...) std::fprintf(stderr, __VA_ARGS__)
#else
#define RELOC_DBG(...) ((void)0)
#endif

namespace NptHook
{

namespace
{

// ============================ 寄存器位掩码 ============================
#define REG_BIT(r)      (1u << (r))
#define REG_RAX         0x0001
#define REG_RCX         0x0002
#define REG_RDX         0x0004
#define REG_RBX         0x0008
#define REG_RSI         0x0040
#define REG_RDI         0x0080
#define REG_R8          0x0100
#define REG_R9          0x0200
#define REG_R10         0x0400
#define REG_R11         0x0800
#define REG_R12         0x1000
#define REG_R13         0x2000
#define REG_R14         0x4000
#define REG_R15         0x8000
#define REG_VOLATILE    (REG_RAX | REG_RCX | REG_RDX | REG_R8 | REG_R9 | REG_R10 | REG_R11)
#define REG_ARGS        (REG_RCX | REG_RDX | REG_R8 | REG_R9)

// ============================ RIP 相对形式分类 ============================
#define RIP_FORM_FAIL       0
#define RIP_FORM_ABS64      1   // lea → movabs（无需暂存）
#define RIP_FORM_R11_CALL   2   // call [rip] → r11 跳板
#define RIP_FORM_R11_JMP    3   // jmp [rip]  → r11 跳板
#define RIP_FORM_SCRATCH    4   // 需要暂存寄存器（存活分析选取）
#define RIP_FORM_NOP        5   // nop [rip] → nop
#define RIP_FORM_DEST       6   // mov r,[rip]：以目标寄存器持地址
                                //   （movabs r,addr; mov r,[r]——只改写
                                //    原指令已写的寄存器，无需死寄存器）

//
// 分类 RIP 相对指令的重写形式。输出：
//   OpBytes/OpLen —— 重编码后的内存指令操作码字节（不含前缀/ModRM）
//   RegField      —— 新 ModRM 的 reg 字段（完整寄存器号 0-15）
//   RmwImmLen     —— 紧随内存操作数之后的立即数长度（C7/83/81/F7 等）
//   AbsDst        —— FORM_ABS64 时输出目标寄存器（0-15）
//
static
int
NpRelocClassifyRip(
    _In_ const NPX_INSN* in,
    _Out_ std::uint8_t* OpBytes,
    _Out_ std::uint8_t* OpLen,
    _Out_ std::uint8_t* RegField,
    _Out_ std::uint8_t* RmwImmLen,
    _Out_ std::uint8_t* AbsDst)
{
    std::uint8_t op = in->Opcode;
    std::uint8_t op2 = in->Opcode2;
    std::uint8_t mrm = in->ModRm;
    std::uint8_t reg = static_cast<std::uint8_t>((mrm >> 3) & 7);
    std::uint8_t digit = reg;
    std::uint8_t rexR = (in->Rex != 0) ? static_cast<std::uint8_t>((in->Rex >> 2) & 1) : 0;
    std::uint8_t regFull = static_cast<std::uint8_t>(reg | (rexR << 3));

    *OpLen = 0;
    *RegField = 0;
    *RmwImmLen = 0;
    *AbsDst = 0;

    switch (op)
    {
    case 0x8B:  // mov r32/r64, [rip]：以目标寄存器持地址（全宽写，语义安全）
        OpBytes[0] = 0x8B; *OpLen = 1; *RegField = regFull;
        return RIP_FORM_DEST;
    case 0x8A:  // mov r8, [rip]：只写低字节，高 56 位会被地址污染 → 需暂存
        OpBytes[0] = 0x8A; *OpLen = 1; *RegField = regFull;
        return RIP_FORM_SCRATCH;
    case 0x8D:  // lea r, [rip] → movabs
        *AbsDst = regFull;
        return RIP_FORM_ABS64;
    case 0x89: case 0x88:   // mov [rip], r32/r8
        OpBytes[0] = op; *OpLen = 1; *RegField = regFull;
        return RIP_FORM_SCRATCH;
    case 0xC7:  // mov dword [rip], imm32
        if (digit != 0) return RIP_FORM_FAIL;
        OpBytes[0] = 0xC7; *OpLen = 1; *RegField = 0;
        *RmwImmLen = in->Prefix66 ? 2 : 4;
        return RIP_FORM_SCRATCH;
    case 0xC6:  // mov byte [rip], imm8
        if (digit != 0) return RIP_FORM_FAIL;
        OpBytes[0] = 0xC6; *OpLen = 1; *RegField = 0; *RmwImmLen = 1;
        return RIP_FORM_SCRATCH;
    case 0x01: case 0x09: case 0x11: case 0x19:
    case 0x21: case 0x29: case 0x31: case 0x39:
    case 0x00: case 0x08: case 0x10: case 0x18:
    case 0x20: case 0x28: case 0x30: case 0x38:
        // add/or/adc/sbb/and/sub/xor/cmp [rip], r
        OpBytes[0] = op; *OpLen = 1; *RegField = regFull;
        return RIP_FORM_SCRATCH;
    case 0x02: case 0x03: case 0x0A: case 0x0B:
    case 0x12: case 0x13: case 0x1A: case 0x1B:
    case 0x22: case 0x23: case 0x2A: case 0x2B:
    case 0x32: case 0x33: case 0x3A: case 0x3B:
        // add/or/adc/sbb/and/sub/xor/cmp r, [rip]
        OpBytes[0] = op; *OpLen = 1; *RegField = regFull;
        return RIP_FORM_SCRATCH;
    case 0x80: case 0x82:  // group1 byte [rip], imm8
        OpBytes[0] = op; *OpLen = 1; *RegField = digit; *RmwImmLen = 1;
        return RIP_FORM_SCRATCH;
    case 0x83:  // group1 [rip], imm8
        OpBytes[0] = op; *OpLen = 1; *RegField = digit; *RmwImmLen = 1;
        return RIP_FORM_SCRATCH;
    case 0x81:  // group1 [rip], imm16/32
        OpBytes[0] = op; *OpLen = 1; *RegField = digit;
        *RmwImmLen = in->Prefix66 ? 2 : 4;
        return RIP_FORM_SCRATCH;
    case 0x85: case 0x84:   // test [rip], r
        OpBytes[0] = op; *OpLen = 1; *RegField = regFull;
        return RIP_FORM_SCRATCH;
    case 0xF7: case 0xF6:   // 仅支持 test [rip], imm（digit 0）
        if (digit != 0) return RIP_FORM_FAIL;
        OpBytes[0] = op; *OpLen = 1; *RegField = 0;
        *RmwImmLen = (op == 0xF7) ? (in->Prefix66 ? 2 : 4) : 1;
        return RIP_FORM_SCRATCH;
    case 0xFF:
        switch (digit)
        {
        case 2: return RIP_FORM_R11_CALL;   // call [rip]
        case 4: return RIP_FORM_R11_JMP;    // jmp [rip]
        case 6:                             // push [rip]
            OpBytes[0] = 0xFF; *OpLen = 1; *RegField = 6;
            return RIP_FORM_SCRATCH;
        default: return RIP_FORM_FAIL;
        }
    case 0x0F:
        switch (op2)
        {
        case 0x10: case 0x11:   // movups/movapd/movsd/movss
        case 0x28: case 0x29:   // movaps/movapd
        case 0x6F: case 0x7F:   // movdqa/movdqu
            OpBytes[0] = 0x0F; OpBytes[1] = op2; *OpLen = 2; *RegField = regFull;
            return RIP_FORM_SCRATCH;
        case 0xC0: case 0xC1:   // xadd r/m, r（含 lock）
            OpBytes[0] = 0x0F; OpBytes[1] = op2; *OpLen = 2; *RegField = regFull;
            return RIP_FORM_SCRATCH;
        case 0x40: case 0x41: case 0x42: case 0x43: // cmovcc r, r/m
        case 0x44: case 0x45: case 0x46: case 0x47: // （条件写目标 → 需暂存）
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            OpBytes[0] = 0x0F; OpBytes[1] = op2; *OpLen = 2; *RegField = regFull;
            return RIP_FORM_SCRATCH;
        case 0xB6: case 0xB7:   // movzx：全宽写，可用目标寄存器持地址
        case 0xBE: case 0xBF:   // movsx：全宽写，可用目标寄存器持地址
            OpBytes[0] = 0x0F; OpBytes[1] = op2; *OpLen = 2; *RegField = regFull;
            return RIP_FORM_DEST;
        case 0x1F:              // nop [rip] → nop
            return RIP_FORM_NOP;
        default:
            return RIP_FORM_FAIL;
        }
    default:
        return RIP_FORM_FAIL;
    }
}

//
// 计算一条指令对 GPR 的读/写掩码（用于存活分析）。
// 未知/无法判定的指令 → readMask 全置（保守：候选判活）。
//
static
void
NpRelocRegUse(
    _In_ const NPX_INSN* in,
    _Out_ std::uint32_t* ReadMask,
    _Out_ std::uint32_t* WriteMask)
{
    std::uint32_t rd = 0, wr = 0;
    std::uint8_t op = in->Opcode;
    std::uint8_t op2 = in->Opcode2;
    std::uint8_t rex = in->Rex;
    std::uint8_t rexR = (rex != 0) ? static_cast<std::uint8_t>((rex >> 2) & 1) : 0;
    std::uint8_t rexB = (rex != 0) ? static_cast<std::uint8_t>(rex & 1) : 0;
    std::uint8_t reg = 0, rm = 0;
    bool rmIsReg = false;

    if (in->HasModRm)
    {
        reg = static_cast<std::uint8_t>(((in->ModRm >> 3) & 7) | (rexR << 3));
        rm = static_cast<std::uint8_t>((in->ModRm & 7) | (rexB << 3));
        rmIsReg = ((in->ModRm >> 6) == 3);
    }

#define RD(r)   rd |= REG_BIT(r)
#define WR(r)   wr |= REG_BIT(r)
#define RDRM()  do { if (rmIsReg) RD(rm); } while (0)
#define RDRMW() do { RD(reg); RDRM(); } while (0)

    switch (op)
    {
    case 0x88: case 0x89:   // mov [m]/r, r8/r
        RD(reg); if (rmIsReg) WR(rm);
        break;
    case 0x8A: case 0x8B:   // mov r, [m]/r
        RDRM(); WR(reg);
        break;
    case 0x8C:              // mov sreg, r/m
        RDRM(); break;
    case 0x8E:              // mov r/m, sreg
        if (rmIsReg) WR(rm);
        break;
    case 0x8D:              // lea
        RDRM(); WR(reg);
        break;
    case 0x63:              // movsxd
        RDRM(); WR(reg);
        break;
    case 0x00: case 0x01: case 0x08: case 0x09:
    case 0x10: case 0x11: case 0x18: case 0x19:
    case 0x20: case 0x21: case 0x28: case 0x29:
    case 0x30: case 0x31:   // add/or/adc/sbb/and/sub/xor [m], r
        RDRMW(); if (rmIsReg) WR(rm);
        break;
    case 0x38: case 0x39:   // cmp [m], r（无写）
        RDRMW();
        break;
    case 0x02: case 0x03: case 0x0A: case 0x0B:
    case 0x12: case 0x13: case 0x1A: case 0x1B:
    case 0x22: case 0x23: case 0x2A: case 0x2B:
    case 0x32: case 0x33:   // add/or/adc/sbb/and/sub/xor r, [m]/r
        RDRM(); WR(reg);
        break;
    case 0x3A: case 0x3B:   // cmp r, [m]/r（无写）
        RDRM();
        break;
    case 0x84: case 0x85:   // test
        RDRMW();
        break;
    case 0x86: case 0x87:   // xchg
        RDRMW(); if (rmIsReg) { WR(rm); WR(reg); }
        break;
    case 0x80: case 0x81: case 0x82: case 0x83: // group1 imm
        RDRM(); if (rmIsReg) WR(rm);
        break;
    case 0xC6: case 0xC7:   // mov [m], imm
        break;
    case 0xF6: case 0xF7: {
        std::uint8_t digit = static_cast<std::uint8_t>((in->ModRm >> 3) & 7);
        switch (digit)
        {
        case 0: case 1:     // test [m], imm
            RDRM(); break;
        case 2: case 3:     // not/neg
            RDRM(); if (rmIsReg) WR(rm); break;
        case 4: case 5:     // mul/imul
        case 6: case 7:     // div/idiv
            RDRM(); RD(0); RD(2); WR(0); WR(2); break;
        }
        break;
    }
    case 0x04: case 0x0C: case 0x14: case 0x1C: // add/or/adc/sbb al, imm8
    case 0x24: case 0x2C: case 0x34:            // and/sub/xor al, imm8
        RD(0); WR(0);
        break;
    case 0x3C:              // cmp al, imm8
        RD(0);
        break;
    case 0x05: case 0x0D: case 0x15: case 0x1D: // add/or/adc/sbb eax/rax, imm
    case 0x25: case 0x2D: case 0x35:            // and/sub/xor eax/rax, imm
        RD(0); WR(0);
        break;
    case 0x3D:              // cmp eax/rax, imm
        RD(0);
        break;
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        RD(op - 0x50);
        break;
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        WR(op - 0x58);
        break;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        // mov r8, imm8：寄存器来自 opcode 低 3 位 + REX.B
        WR((op & 7) | (rexB << 3));
        break;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        // mov r, imm：同上
        WR((op & 7) | (rexB << 3));
        break;
    case 0x69: case 0x6B:   // imul r, r/m, imm
        RDRM(); WR(reg);
        break;
    case 0xC0: case 0xC1:   // shifts r/m, imm8
        RDRM(); if (rmIsReg) WR(rm);
        break;
    case 0xD0: case 0xD1:   // shifts r/m, 1
        RDRM(); if (rmIsReg) WR(rm);
        break;
    case 0xD2: case 0xD3:   // shifts r/m, cl
        RDRM(); RD(1); if (rmIsReg) WR(rm);
        break;
    case 0xFE:              // inc/dec r/m
        RDRM(); if (rmIsReg) WR(rm);
        break;
    case 0xFF: {
        std::uint8_t digit = static_cast<std::uint8_t>((in->ModRm >> 3) & 7);
        switch (digit)
        {
        case 0: case 1:     // inc/dec
            RDRM(); if (rmIsReg) WR(rm); break;
        case 2: case 4:     // call/jmp [m]
        case 3: case 5:
            RD(1); RD(2); RD(8); RD(9);
            wr |= REG_VOLATILE;
            break;
        case 6: case 7:     // push [m]
            RDRM(); break;
        }
        break;
    }
    case 0x68: case 0x6A:   // push imm
        break;
    case 0x98:              // cwde
        WR(0); break;
    case 0x99:              // cdq/cqo
        WR(2); break;
    case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97: // xchg r, rax
        RD(0); WR(0);
        RD(op - 0x91); WR(op - 0x91);
        break;
    case 0xA8:              // test al, imm8
        RD(0); break;
    case 0xA9:              // test eax/rax, imm
        RD(0); break;
    case 0xA0: case 0xA2:   // mov al/ax/eax/rax, moffs
        WR(0); break;
    case 0xA1: case 0xA3:   // mov moffs, al/...
        RD(0); break;
    case 0xA4: case 0xA5: case 0xA6: case 0xA7: // movs/cmps
    case 0xAA: case 0xAB: case 0xAC: case 0xAD: // stos/lods
    case 0xAE: case 0xAF:                        // scas
        RD(0); RD(1); RD(6); RD(7); WR(0); WR(1); WR(6); WR(7);
        break;
    case 0xE4: case 0xE5: case 0xE6: case 0xE7: // in/out imm
        RD(0); WR(0); break;
    case 0xEC: case 0xED: case 0xEE: case 0xEF: // in/out dx
        RD(0); RD(2); WR(0); break;
    case 0xE8:              // call rel32（DFS 特判）
        break;
    case 0xE9: case 0xEB:   // jmp rel32/rel8（仅标志位）
        break;
    case 0x70: case 0x71: case 0x72: case 0x73: // jcc rel8（仅标志位）
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        break;
    case 0x0F:
        //
        // SSE 无 GPR 操作数（宽范围；0x6E/0x7E/0x2A/0x2C/0x2D/0x90-0x9F 例外）
        //
        if ((op2 >= 0x10 && op2 <= 0x1F) ||
            (op2 >= 0x28 && op2 <= 0x3F) ||
            (op2 >= 0x50 && op2 <= 0x6D) ||
            (op2 >= 0x70 && op2 <= 0x7D) ||
            (op2 >= 0xD0 && op2 <= 0xDF))
        {
            break;
        }
        switch (op2)
        {
        case 0x6E:              // movd/movq xmm, r/m
            RDRM(); break;
        case 0x7E:              // movd/movq r/m, xmm（REX.W+66 = movq r64, xmm）
            if (rmIsReg) WR(rm); break;
        case 0x2A: case 0x2C: case 0x2D:    // cvtsi2ss/sd 等（读 GPR rm）
            RDRM(); break;
        case 0x80: case 0x81: case 0x82: case 0x83: // jcc rel32（仅标志位）
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            break;
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: // setcc r/m8
            if (rmIsReg) WR(rm); break;
        case 0xB6: case 0xB7: case 0xBE: case 0xBF: // movzx/movsx
            RDRM(); WR(reg); break;
        case 0xAF:          // imul r, r/m
            RDRM(); WR(reg); break;
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: // cmovcc
            RDRM(); WR(reg); break;
        case 0xC0: case 0xC1:   // xadd
            RDRMW(); if (rmIsReg) WR(rm); WR(reg); break;
        case 0xA2:              // cpuid
            RD(0); RD(1); WR(0); WR(1); WR(2); WR(3); break;
        case 0xB8: case 0xBC: case 0xBD:    // popcnt/tzcnt/lzcnt
            RDRM(); WR(reg); break;
        case 0x10: case 0x11: case 0x28: case 0x29:
        case 0x6F: case 0x7F:               // SSE（不涉 GPR）
        case 0x1F:                          // nop
            break;
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
        case 0x0B: case 0x0E: case 0x30: case 0x31: case 0x32:
        case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x77: case 0xA0: case 0xA1: case 0xA8:
        case 0xA9: case 0xAA: case 0xC8: case 0xC9: case 0xCA:
        case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            break;                          // 无 GPR 操作数
        default:
            rd = 0xFFFFFFFFu;               // 未知：保守全读
            break;
        }
        break;
    default:
        rd = 0xFFFFFFFFu;                   // 未知：保守全读
        break;
    }

#undef RD
#undef WR
#undef RDRM
#undef RDRMW

    *ReadMask = rd;
    *WriteMask = wr;
}

// ============================ 存活分析（记忆化前向 DFS） ============================
//
// dead(off)：从 off 沿所有可达路径，候选寄存器在到达任何读取之前
// 是否必然被写入。记忆化保证每个偏移只计算一次（有界终止）：
//   Memo[off]：0=未计算；1=计算中（环 → 乐观假定死，首次处理时
//              该指令自身的读/写检查已执行，故假定是可靠的）；
//              2=死；3=活。
//
#define NP_RELOC_DFS_DEPTH     1024

static
bool
NpRelocDeadOnPath(
    _In_ const std::uint8_t* Block,
    _In_ std::uint32_t CodeEnd,
    _In_ std::uint32_t Off,
    _In_ std::uint32_t RegBit,
    _In_ std::uint32_t Depth,
    _Inout_ std::uint8_t* Memo)
{
    if (Off >= CodeEnd)
    {
        return true;                        // 代码区尽头：路径上无更多读取
    }
    if (Depth > NP_RELOC_DFS_DEPTH)
    {
        return false;                       // 深度保险：保守判活
    }

    std::uint8_t st = Memo[Off];
    if (st == 2) return true;
    if (st == 3) return false;
    if (st == 1) return true;               // 环：乐观假定死
    Memo[Off] = 1;
    RELOC_DBG("[reloc]   dfs off=0x%x regbit=%08x\n", Off, (unsigned)RegBit);

    NPX_INSN in;
    std::uint32_t len = NpDisasmDecode(Block + Off, 15, &in);
    if (len == 0 || in.Length == 0)
    {
        Memo[Off] = 3;
        return false;
    }

    //
    // 路径终止类：ret/retf/int3/iret/ud2
    //
    if (in.Opcode == 0xC3 || in.Opcode == 0xC2 || in.Opcode == 0xCB ||
        in.Opcode == 0xCA || in.Opcode == 0xCC || in.Opcode == 0xCF ||
        in.Opcode == 0x0B)
    {
        Memo[Off] = 2;
        return true;
    }

    std::uint32_t rd = 0, wr = 0;
    NpRelocRegUse(&in, &rd, &wr);
    bool result;
    if ((rd & RegBit) != 0)
    {
        result = false;                     // 读取 → 活
    }
    else if ((wr & RegBit) != 0)
    {
        result = true;                      // 先写 → 死
    }
    else
    {
        switch (in.Kind)
        {
        case NPX_KIND_JMP_REL32:
        case NPX_KIND_JMP_REL8:
        {
            std::uint32_t tgt = Off + len + static_cast<std::uint32_t>(in.RelDisp);
            if (tgt < CodeEnd)
            {
                result = NpRelocDeadOnPath(Block, CodeEnd, tgt, RegBit,
                                           Depth + 1, Memo);
            }
            else
            {
                //
                // 出块跳转 = 尾调用：参数寄存器可能被转发（活），其余
                // 寄存器按 ABI 不被被调方依赖（死）。
                //
                result = (RegBit & REG_ARGS) == 0;
            }
            break;
        }
        case NPX_KIND_JCC_REL8:
        case NPX_KIND_JCC_REL32:
        {
            std::uint32_t tgt = Off + len + static_cast<std::uint32_t>(in.RelDisp);
            bool fall = NpRelocDeadOnPath(Block, CodeEnd, Off + len, RegBit,
                                          Depth + 1, Memo);
            bool br = (tgt < CodeEnd)
                ? NpRelocDeadOnPath(Block, CodeEnd, tgt, RegBit, Depth + 1, Memo)
                : false;
            result = fall && br;
            break;
        }
        case NPX_KIND_CALL_REL32:
            //
            // call：参数寄存器被读取（活）；volatile 寄存器被调用方
            // clobber（死）。
            //
            if ((RegBit & REG_ARGS) != 0)
            {
                result = false;
            }
            else if ((RegBit & REG_VOLATILE) != 0)
            {
                result = true;
            }
            else
            {
                result = NpRelocDeadOnPath(Block, CodeEnd, Off + len, RegBit,
                                           Depth + 1, Memo);
            }
            break;
        default:
            result = NpRelocDeadOnPath(Block, CodeEnd, Off + len, RegBit,
                                       Depth + 1, Memo);
            break;
        }
    }

    Memo[Off] = result ? 2 : 3;
    return result;
}

//
// 为重写点寻找可安全用作暂存的死寄存器。
// UsedMask = 被重写指令自身读写的寄存器（候选须避开）。
// 返回 0-15；-1 = 无可用（调用方应拒绝）。
//
static
int
NpRelocFindScratch(
    _In_ const std::uint8_t* Block,
    _In_ std::uint32_t CodeEnd,
    _In_ std::uint32_t InsnOff,
    _In_ std::uint32_t InsnLen,
    _In_ std::uint32_t UsedMask)
{
    //
    // 候选顺序：先 volatile，再非易失。
    // 排除 rsp/rbp/r12/r13（mod=00 编码歧义：rm=4 需 SIB、rm=5 是 RIP 相对）。
    //
    static const std::uint8_t s_Candidates[] = {
        0, 1, 2, 8, 9, 10, 11,   // rax rcx rdx r8 r9 r10 r11
        3, 6, 7, 14, 15,         // rbx rsi rdi r14 r15
    };

    std::uint8_t* memo = static_cast<std::uint8_t*>(
        NP_RELOC_ALLOC(NP_RELOC_BLOCK_SIZE));
    if (memo == nullptr)
    {
        return -1;
    }
    for (std::uint8_t c : s_Candidates)
    {
        std::uint32_t bit = REG_BIT(c);
        if ((UsedMask & bit) != 0)
        {
            continue;
        }
        for (std::uint32_t k = 0; k < NP_RELOC_BLOCK_SIZE; k++)
        {
            memo[k] = 0;
        }
        bool dead = NpRelocDeadOnPath(Block, CodeEnd, InsnOff + InsnLen, bit, 0,
                                      memo);
        RELOC_DBG("[reloc] scratch: insn@0x%x cand=r%u dead=%d\n",
                  InsnOff, (unsigned)c, dead ? 1 : 0);
        if (dead)
        {
            NP_RELOC_FREE(memo);
            return c;
        }
    }
    NP_RELOC_FREE(memo);
    return -1;
}

// ============================ 发射辅助 ============================

//
// mov r64, imm64（movabs）：10 字节
//
static
std::uint32_t
EmitMovImm64(
    _Out_ std::uint8_t* P,
    _In_ std::uint8_t Reg,
    _In_ std::uintptr_t Imm)
{
    P[0] = static_cast<std::uint8_t>(0x48 | ((Reg >> 3) & 1));
    P[1] = static_cast<std::uint8_t>(0xB8 | (Reg & 7));
    std::uint64_t v = static_cast<std::uint64_t>(Imm);
    for (std::uint32_t k = 0; k < 8; k++)
    {
        P[2 + k] = static_cast<std::uint8_t>((v >> (8 * k)) & 0xFF);
    }
    return 10;
}

//
// jcc 出块 → 反向短跳 + r11 跳板（15 字节）
// CondCode = 原始条件码低 4 位（0-15）
// 注意：call/jmp r11 需要 REX.B（41 FF D3 / 41 FF E3）——
// 裸 FF D3 是 call rbx，会调用垃圾寄存器。
//
static
std::uint32_t
EmitJccThunk(
    _Out_ std::uint8_t* P,
    _In_ std::uint8_t CondCode,
    _In_ std::uintptr_t Target)
{
    P[0] = static_cast<std::uint8_t>(0x70 | (CondCode ^ 1));  // 反向条件
    P[1] = 13;                              // 跳过下方 13 字节
    std::uint32_t n = EmitMovImm64(P + 2, 11, Target);
    P[2 + n] = 0x41;                        // REX.B → r11
    P[2 + n + 1] = 0xFF;
    P[2 + n + 2] = 0xE3;                    // jmp r11
    return static_cast<std::uint32_t>(2 + n + 3);
}

//
// RIP 相对内存指令重编码：mov <scratch>, imm64 + [lock] + [66] + [f2/f3]
//                            + [REX] + 操作码 + ModRM' + [imm]
// 返回总长度；失败返回 0。
//
static
std::uint32_t
EmitScratchMemOp(
    _Out_ std::uint8_t* P,
    _In_ const NPX_INSN* in,
    _In_ std::uint8_t Scratch,
    _In_ std::uintptr_t Target,
    _In_ const std::uint8_t* OpBytes,
    _In_ std::uint8_t OpLen,
    _In_ std::uint8_t RegField,
    _In_ std::uint8_t RmwImmLen,
    _In_ const std::uint8_t* SrcInsn)
{
    std::uint32_t n = EmitMovImm64(P, Scratch, Target);

    if (in->PrefixLock)
    {
        P[n++] = 0xF0;
    }
    if (in->Prefix66)
    {
        P[n++] = 0x66;
    }
    if (in->PrefixRep)
    {
        P[n++] = in->PrefixRep;
    }

    //
    // 重编码 REX：W 沿用原指令；R = RegField 高位；B = Scratch 高位
    //
    std::uint8_t rexW = in->RexW;
    std::uint8_t rexR = static_cast<std::uint8_t>((RegField >> 3) & 1);
    std::uint8_t rexB = static_cast<std::uint8_t>((Scratch >> 3) & 1);
    if (in->Rex != 0 || rexR != 0 || rexB != 0)
    {
        P[n++] = static_cast<std::uint8_t>(0x40 | (rexW ? 8 : 0) |
                                          (rexR ? 4 : 0) | rexB);
    }
    else if (rexW)
    {
        P[n++] = 0x48;
    }

    for (std::uint8_t k = 0; k < OpLen; k++)
    {
        P[n++] = OpBytes[k];
    }

    //
    // ModRM'：mod=00，reg=RegField，rm=Scratch
    //
    P[n++] = static_cast<std::uint8_t>(((RegField & 7) << 3) | (Scratch & 7));

    //
    // 立即数（源指令 modrm 后 = disp32，再后 = imm）
    //
    if (RmwImmLen != 0)
    {
        std::uint32_t srcImmOff = in->ModRmOff + 1 + 4;
        if (srcImmOff + RmwImmLen > in->Length)
        {
            return 0;
        }
        for (std::uint8_t k = 0; k < RmwImmLen; k++)
        {
            P[n++] = SrcInsn[srcImmOff + k];
        }
    }

    return n;
}

// ============================ 主流程 ============================

typedef struct _NP_RELOC_REC
{
    std::uint32_t OrigOff;
    std::uint32_t NewOff;
    std::uint8_t  OrigLen;
    std::uint8_t  NewLen;
    std::uint8_t  Kind;         // NPX_KIND_*
    std::uint8_t  Rewrite;      // 0=复制；1=改写（含 rel8→rel32 扩宽）
    std::uint8_t  Scratch;      // 改写暂存寄存器
    std::uintptr_t AbsTarget;   // 改写绝对目标（出块时）
    std::uint32_t  RelTarget;   // 块内相对目标（原始偏移）
} NP_RELOC_REC;

#define NP_RELOC_MAX_REC       8192

} // namespace

std::uint32_t
NpRelocMapLookup(
    _In_ const NP_RELOC_MAP* Map,
    _In_ std::uint32_t MapCount,
    _In_ std::uint32_t Off)
{
    if (Map == nullptr || MapCount == 0)
    {
        return Off;
    }

    std::uint32_t lo = 0, hi = MapCount;
    while (lo < hi)
    {
        std::uint32_t mid = (lo + hi) / 2;
        if (Map[mid].OrigOff <= Off)
        {
            lo = mid + 1;
        }
        else
        {
            hi = mid;
        }
    }
    if (lo == 0)
    {
        return Off;                     // 首个变化点之前：delta=0
    }
    const NP_RELOC_MAP* e = &Map[lo - 1];
    return e->NewOff + (Off - e->OrigOff);
}

bool
NpRelocRelocateBlock(
    _In_ const std::uint8_t* SrcBlock,
    _In_ std::uintptr_t OrigPageVa,
    _In_ std::uint32_t FuncEntryOff,
    _In_reads_opt_(RangeCount) const NP_RELOC_RANGE* Ranges,
    _In_ std::uint32_t RangeCount,
    _Out_writes_(OutCap) std::uint8_t* OutBuf,
    _In_ std::uint32_t OutCap,
    _Out_ NP_RELOC_RESULT* Result)
{
    (void)FuncEntryOff;

    if (SrcBlock == nullptr || OutBuf == nullptr || Result == nullptr)
    {
        return false;
    }
    if (Result->Map == nullptr || Result->MapCapacity == 0)
    {
        return false;
    }

    Result->FailKind = 0;
    Result->FailOff = 0;

    NP_RELOC_REC* recs = static_cast<NP_RELOC_REC*>(
        NP_RELOC_ALLOC(sizeof(NP_RELOC_REC) * NP_RELOC_MAX_REC));
    if (recs == nullptr)
    {
        Result->FailKind = 2;
        Result->FailOff = 0;
        return false;
    }

#define RELOC_FAIL(kind, off) \
    do { Result->FailKind = (kind); Result->FailOff = (off); \
         NP_RELOC_FREE(recs); return false; } while (0)

    std::uint32_t recCount = 0;
    std::uint32_t curNew = 0;
    std::uint32_t mapCount = 0;

    //
    // 处理一个代码区间内的全部指令（解码 + 分类 + 布局推进）。
    // RangeEnd 同时约束存活分析的扫描范围。
    //
    auto ProcessRange = [&](std::uint32_t rangeBeg, std::uint32_t rangeEnd) -> bool
    {
        for (std::uint32_t off = rangeBeg; off < rangeEnd; )
        {
            NPX_INSN in;
            std::uint32_t len = NpDisasmDecode(SrcBlock + off, 15, &in);
            if (len == 0 || in.Length == 0 || recCount >= NP_RELOC_MAX_REC)
            {
                RELOC_FAIL(1, off);
            }

            if (off + len > rangeEnd || off + len > NP_RELOC_BLOCK_SIZE)
            {
                //
                // 区间/块尾的残缺指令（函数体跨界到下页）：剩余字节原样
                // 复制——该指令起始于块内、延续到块外，克隆里无法正确
                // 重定位；实际执行流会在块边界前跳走（真页恒等执行），
                // 这里仅保持布局连续。
                //
                std::uint32_t tail = rangeEnd - off;
                for (std::uint32_t k = 0; k < tail; k++)
                {
                    OutBuf[curNew + k] = SrcBlock[off + k];
                }
                curNew += tail;
                off = rangeEnd;
                break;
            }

            NP_RELOC_REC* r = &recs[recCount];
            r->OrigOff = off;
            r->NewOff = curNew;
            r->OrigLen = static_cast<std::uint8_t>(len);
            r->Kind = static_cast<std::uint8_t>(in.Kind);
            r->Rewrite = 0;
            r->Scratch = 0;
            r->AbsTarget = 0;
            r->RelTarget = 0;
            r->NewLen = static_cast<std::uint8_t>(len);

            if (in.Kind == NPX_KIND_CALL_REL32 ||
                in.Kind == NPX_KIND_JMP_REL32 ||
                in.Kind == NPX_KIND_JMP_REL8 ||
                in.Kind == NPX_KIND_JCC_REL8 ||
                in.Kind == NPX_KIND_JCC_REL32)
            {
                std::int64_t tgt = static_cast<std::int64_t>(off) + len + in.RelDisp;
                if (tgt >= 0 && tgt < NP_RELOC_BLOCK_SIZE)
                {
                    r->RelTarget = static_cast<std::uint32_t>(tgt);
                    if (in.Kind == NPX_KIND_JMP_REL8 || in.Kind == NPX_KIND_JCC_REL8)
                    {
                        //
                        // 块内 rel8 分支扩为 rel32：布局膨胀后防位移溢出
                        //
                        r->Rewrite = 1;
                        r->NewLen = (in.Kind == NPX_KIND_JCC_REL8) ? 6 : 5;
                    }
                }
                else
                {
                    r->Rewrite = 1;
                    r->AbsTarget = OrigPageVa + static_cast<std::uintptr_t>(tgt);
                    switch (in.Kind)
                    {
                    case NPX_KIND_CALL_REL32: r->NewLen = 13; break;
                    case NPX_KIND_JMP_REL32:
                    case NPX_KIND_JMP_REL8:   r->NewLen = 13; break;
                    default:                  r->NewLen = 15; break;   // jcc
                    }
                }
            }
            else if (in.Kind == NPX_KIND_RIP_RELATIVE)
            {
                std::int32_t disp = 0;
                if (in.RipDispOff != 0 &&
                    static_cast<std::uint32_t>(in.RipDispOff) + 4 <= len)
                {
                    disp = *reinterpret_cast<const std::int32_t*>(
                        SrcBlock + off + in.RipDispOff);
                }
                std::int64_t tgt = static_cast<std::int64_t>(off) + len + disp;
                if (tgt >= 0 && tgt < NP_RELOC_BLOCK_SIZE)
                {
                    r->RelTarget = static_cast<std::uint32_t>(tgt);     // 块内数据：保持相对
                }
                else
                {
                    std::uint8_t opBytes[4];
                    std::uint8_t opLen = 0, regField = 0, rmwImmLen = 0, absDst = 0;
                    int form = NpRelocClassifyRip(&in, opBytes, &opLen, &regField,
                                                  &rmwImmLen, &absDst);
                    std::uintptr_t absTarget =
                        OrigPageVa + static_cast<std::uintptr_t>(tgt);

                    switch (form)
                    {
                    case RIP_FORM_ABS64:
                        r->Rewrite = 1;
                        r->AbsTarget = absTarget;
                        r->Scratch = absDst;
                        r->NewLen = 10;
                        break;
                    case RIP_FORM_R11_CALL:
                    case RIP_FORM_R11_JMP:
                        r->Rewrite = 1;
                        r->AbsTarget = absTarget;
                        r->Scratch = 11;
                        r->NewLen = 13;
                        break;
                    case RIP_FORM_NOP:
                        r->Rewrite = 1;
                        r->NewLen = 1;
                        break;
                    case RIP_FORM_DEST:
                    {
                        //
                        // movabs <dst>, addr; <op> <dst>, [<dst>]
                        // 10B + [66] + [REX] + 操作码 + ModRM
                        //
                        std::uint32_t memLen = 1 + opLen;   // ModRM + 操作码字节
                        if (in.Prefix66) memLen++;
                        if (in.Rex != 0 || regField >= 8) memLen++;  // REX（R+B）
                        r->Rewrite = 1;
                        r->AbsTarget = absTarget;
                        r->Scratch = regField;              // 目标寄存器持地址
                        r->NewLen = static_cast<std::uint8_t>(10 + memLen);
                        break;
                    }
                    case RIP_FORM_SCRATCH:
                    {
                        std::uint32_t used = 0;
                        if (in.HasModRm)
                        {
                            std::uint8_t rexR = (in.Rex != 0) ?
                                static_cast<std::uint8_t>((in.Rex >> 2) & 1) : 0;
                            std::uint8_t rexB = (in.Rex != 0) ?
                                static_cast<std::uint8_t>(in.Rex & 1) : 0;
                            used |= REG_BIT(((in.ModRm >> 3) & 7) | (rexR << 3));
                            if (((in.ModRm >> 6) & 3) == 3)
                            {
                                used |= REG_BIT((in.ModRm & 7) | (rexB << 3));
                            }
                        }
                        int scratch = NpRelocFindScratch(SrcBlock, rangeEnd,
                                                         off, len, used);
                        if (scratch < 0)
                        {
                            RELOC_FAIL(3, off);
                        }

                        std::uint32_t memLen = 1 + opLen;   // ModRM + 操作码字节
                        if (in.PrefixLock) memLen++;
                        if (in.Prefix66) memLen++;
                        if (in.PrefixRep) memLen++;
                        if (in.Rex != 0 || regField >= 8 || scratch >= 8) memLen++;

                        r->Rewrite = 1;
                        r->AbsTarget = absTarget;
                        r->Scratch = static_cast<std::uint8_t>(scratch);
                        r->NewLen = static_cast<std::uint8_t>(
                            10 + memLen + rmwImmLen);
                        break;
                    }
                    default:
                        RELOC_FAIL(4, off);
                    }
                }
            }

            //
            // 布局推进；记录变化点。
            // 映射表以【重写指令源跨度的结束边界】为键：布局位移在
            // 重写指令之后才生效，边界键保证 MapLookup(下一条指令
            // 起始) 正确（否则插值会少算 NewLen-OrigLen）。
            //
            if (r->Rewrite)
            {
                if (mapCount < Result->MapCapacity)
                {
                    Result->Map[mapCount].OrigOff = r->OrigOff + r->OrigLen;
                    Result->Map[mapCount].NewOff = r->NewOff + r->NewLen;
                    mapCount++;
                }
                else
                {
                    RELOC_FAIL(2, r->OrigOff);
                }
            }

            curNew += r->NewLen;
            recCount++;
            off += len;
        }
        return true;
    };

    //
    // Pass 1：按代码区间处理；区间之间（跳转表/对齐/填充）原样复制。
    //
    std::uint32_t srcCursor = 0;
    for (std::uint32_t ri = 0; ri < RangeCount; ri++)
    {
        if (Ranges[ri].End > NP_RELOC_BLOCK_SIZE || Ranges[ri].Beg >= Ranges[ri].End)
        {
            RELOC_FAIL(5, Ranges[ri].Beg);
        }
        if (Ranges[ri].Beg < srcCursor)
        {
            RELOC_FAIL(5, Ranges[ri].Beg);  // 区间必须升序且不相交
        }
        std::uint32_t gapLen = Ranges[ri].Beg - srcCursor;
        if (curNew + gapLen > OutCap)
        {
            RELOC_FAIL(6, Ranges[ri].Beg);
        }
        for (std::uint32_t k = 0; k < gapLen; k++)
        {
            OutBuf[curNew + k] = SrcBlock[srcCursor + k];
        }
        curNew += gapLen;

        if (!ProcessRange(Ranges[ri].Beg, Ranges[ri].End))
        {
            // RELOC_FAIL（lambda 内）已释放 recs，这里不能二次释放。
            return false;
        }
        srcCursor = Ranges[ri].End;
    }

    // 尾部缝隙
    {
        std::uint32_t gapLen = NP_RELOC_BLOCK_SIZE - srcCursor;
        if (curNew + gapLen > OutCap)
        {
            RELOC_FAIL(6, srcCursor);
        }
        for (std::uint32_t k = 0; k < gapLen; k++)
        {
            OutBuf[curNew + k] = SrcBlock[srcCursor + k];
        }
        curNew += gapLen;
    }

    if (curNew > OutCap)
    {
        RELOC_FAIL(6, NP_RELOC_BLOCK_SIZE);
    }

    //
    // Pass 2：发射
    //
    for (std::uint32_t i = 0; i < recCount; i++)
    {
        const NP_RELOC_REC* r = &recs[i];
        std::uint8_t* dst = OutBuf + r->NewOff;
        const std::uint8_t* src = SrcBlock + r->OrigOff;

        if (!r->Rewrite)
        {
            //
            // 原样复制；块内相对目标修正位移
            //
            for (std::uint32_t k = 0; k < r->OrigLen; k++)
            {
                dst[k] = src[k];
            }
            if (r->Kind == NPX_KIND_CALL_REL32 ||
                r->Kind == NPX_KIND_JMP_REL32 ||
                r->Kind == NPX_KIND_JCC_REL32)
            {
                NPX_INSN in;
                std::uint32_t len = NpDisasmDecode(src, 15, &in);
                std::uint32_t tgtNew = NpRelocMapLookup(Result->Map, mapCount,
                                                        r->RelTarget);
                std::int32_t newDisp =
                    static_cast<std::int32_t>(tgtNew - (r->NewOff + len));
                *reinterpret_cast<std::int32_t*>(dst + in.RelDispOff) = newDisp;
            }
            else if (r->Kind == NPX_KIND_RIP_RELATIVE)
            {
                NPX_INSN in;
                std::uint32_t len = NpDisasmDecode(src, 15, &in);
                std::uint32_t tgtNew = NpRelocMapLookup(Result->Map, mapCount,
                                                        r->RelTarget);
                std::int32_t newDisp =
                    static_cast<std::int32_t>(tgtNew - (r->NewOff + len));
                *reinterpret_cast<std::int32_t*>(dst + in.RipDispOff) = newDisp;
            }
            continue;
        }

        //
        // 改写
        //
        switch (r->Kind)
        {
        case NPX_KIND_CALL_REL32:
        {
            std::uint32_t n = EmitMovImm64(dst, 11, r->AbsTarget);
            dst[n] = 0x41;                  // REX.B → r11
            dst[n + 1] = 0xFF;
            dst[n + 2] = 0xD3;              // call r11
            break;
        }
        case NPX_KIND_JMP_REL32:
        case NPX_KIND_JMP_REL8:
            if (r->AbsTarget != 0)
            {
                //
                // 出块：mov r11,imm64; jmp r11
                //
                std::uint32_t n = EmitMovImm64(dst, 11, r->AbsTarget);
                dst[n] = 0x41;              // REX.B → r11
                dst[n + 1] = 0xFF;
                dst[n + 2] = 0xE3;
            }
            else
            {
                //
                // 块内 rel8 → rel32（E9 cd）
                //
                dst[0] = 0xE9;
                std::uint32_t tgtNew = NpRelocMapLookup(Result->Map, mapCount,
                                                        r->RelTarget);
                std::int32_t newDisp =
                    static_cast<std::int32_t>(tgtNew - (r->NewOff + 5));
                *reinterpret_cast<std::int32_t*>(dst + 1) = newDisp;
            }
            break;
        case NPX_KIND_JCC_REL8:
        case NPX_KIND_JCC_REL32:
            if (r->AbsTarget != 0)
            {
                //
                // 出块：反向短跳 + r11 跳板
                //
                std::uint8_t cond = src[0];
                if (cond == 0x0F)
                {
                    cond = static_cast<std::uint8_t>(src[1] & 0x0F);
                }
                else
                {
                    cond = static_cast<std::uint8_t>(cond & 0x0F);
                }
                EmitJccThunk(dst, cond, r->AbsTarget);
            }
            else
            {
                //
                // 块内 rel8 → 0F 8x rel32
                //
                dst[0] = 0x0F;
                dst[1] = static_cast<std::uint8_t>(0x80 | (src[0] & 0x0F));
                std::uint32_t tgtNew = NpRelocMapLookup(Result->Map, mapCount,
                                                        r->RelTarget);
                std::int32_t newDisp =
                    static_cast<std::int32_t>(tgtNew - (r->NewOff + 6));
                *reinterpret_cast<std::int32_t*>(dst + 2) = newDisp;
            }
            break;
        case NPX_KIND_RIP_RELATIVE:
        {
            NPX_INSN in;
            NpDisasmDecode(src, 15, &in);
            std::uint8_t opBytes[4];
            std::uint8_t opLen = 0, regField = 0, rmwImmLen = 0, absDst = 0;
            int form = NpRelocClassifyRip(&in, opBytes, &opLen, &regField,
                                          &rmwImmLen, &absDst);
            if (form == RIP_FORM_ABS64)
            {
                EmitMovImm64(dst, absDst, r->AbsTarget);
            }
            else if (form == RIP_FORM_NOP)
            {
                dst[0] = 0x90;
            }
            else if (form == RIP_FORM_DEST)
            {
                //
                // movabs <dst>, addr; <op> <dst>, [<dst>]
                //
                std::uint32_t n = EmitMovImm64(dst, r->Scratch, r->AbsTarget);
                if (in.Prefix66)
                {
                    dst[n++] = 0x66;
                }
                std::uint8_t rexW = in.RexW;
                std::uint8_t hi = static_cast<std::uint8_t>((r->Scratch >> 3) & 1);
                std::uint8_t rex = static_cast<std::uint8_t>(
                    0x40 | (rexW ? 8 : 0) | (hi ? 5 : 0));  // R + B
                if (rex != 0x40 || in.Rex != 0)
                {
                    dst[n++] = rex;
                }
                for (std::uint8_t k = 0; k < opLen; k++)
                {
                    dst[n++] = opBytes[k];
                }
                dst[n++] = static_cast<std::uint8_t>(
                    ((regField & 7) << 3) | (r->Scratch & 7));
                if (n != r->NewLen)
                {
                    RELOC_FAIL(7, r->OrigOff);
                }
            }
            else if (form == RIP_FORM_R11_CALL || form == RIP_FORM_R11_JMP)
            {
                std::uint32_t n = EmitMovImm64(dst, 11, r->AbsTarget);
                dst[n] = 0x41;              // REX.B → r11
                dst[n + 1] = 0xFF;
                dst[n + 2] = (form == RIP_FORM_R11_CALL) ? 0xD3 : 0xE3;
            }
            else if (form == RIP_FORM_SCRATCH)
            {
                std::uint32_t n = EmitScratchMemOp(dst, &in, r->Scratch,
                                                   r->AbsTarget, opBytes, opLen,
                                                   regField, rmwImmLen, src);
                if (n == 0 || n != r->NewLen)
                {
                    RELOC_FAIL(7, r->OrigOff);
                }
            }
            else
            {
                RELOC_FAIL(4, r->OrigOff);
            }
            break;
        }
        default:
            RELOC_FAIL(8, r->OrigOff);
        }
    }

    Result->OutLen = curNew;
    Result->MapCount = mapCount;
    NP_RELOC_FREE(recs);
    return true;

#undef RELOC_FAIL
}

} // namespace NptHook
