/*!
    @file       NpDisasm.cpp

    @brief      services/NpDisasm：x64 指令解码器（长度 + 分类）。

    @details    按 x64 指令编码顺序逐段解析：
                    前缀 → REX → 操作码 → ModRM/SIB → 位移 → 立即数
                返回指令长度，并识别两类需要重定位的引用：
                - 相对跳转（E8/E9/EB/70-7F/0F 80-8F）
                - RIP 相对内存操作数（ModRM mod=00 rm=101，无段前缀）

                覆盖编译器在内核函数中会生成的全部常见指令
                （mov/push/pop/sub/add/lea/test/cmp/and/or/xor/imul/
                movzx/movsx/shld/shrd/setcc/jcc/call/jmp/ret/nop/int3/
                x87/SSE 等）。VEX/EVEX（AVX）编码不支持——内核代码
                （WDK 默认编译选项）不会生成，若出现则解码失败，
                调用方（Hook 安装/克隆重定位）会拒绝而非产生错误长度。

                与 WDK 无关的纯逻辑，可在主机上用任意 C++ 编译器
                做单元测试（见 tests/）。
  */
#include "NpDisasm.hpp"

namespace NptHook
{

namespace
{

/*!
    @brief      核心解码：前缀/REX/操作码/ModRM/SIB/位移/立即数。
                与 GetInstructionLength 等价（长度一致），并填充分类字段。
 */
std::uint32_t
NpDisasmDecodeCore(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MaxLength,
    _Out_opt_ NPX_INSN* Out)
{
    if (Code == nullptr)
    {
        return 0;
    }
    if (MaxLength == 0 || MaxLength > 15)
    {
        MaxLength = 15;
    }

    NPX_INSN info;
    for (std::uint32_t k = 0; k < sizeof(info); k++)
    {
        reinterpret_cast<std::uint8_t*>(&info)[k] = 0;
    }

    std::uint32_t i = 0;
    bool prefix66 = false;
    bool prefix67 = false;
    std::uint8_t prefixRep = 0;
    std::uint8_t prefixLock = 0;
    std::uint8_t prefixSeg = 0;

    //
    // 1. Legacy 前缀（可任意顺序、可重复）
    //
    while (i < MaxLength)
    {
        std::uint8_t b = Code[i];
        if (b == 0x66)
        {
            prefix66 = true;
            ++i;
            continue;
        }
        if (b == 0x67)
        {
            prefix67 = true;
            ++i;
            continue;
        }
        if (b == 0xF2 || b == 0xF3)
        {
            prefixRep = b;
            ++i;
            continue;
        }
        if (b == 0xF0)
        {
            prefixLock = 0xF0;
            ++i;
            continue;
        }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65)
        {
            prefixSeg = b;
            ++i;
            continue;
        }
        break;
    }

    //
    // 2. REX 前缀
    //
    bool rexW = false;
    std::uint8_t rex = 0;
    if (i < MaxLength && (Code[i] & 0xF0) == 0x40)
    {
        rex = Code[i];
        rexW = (Code[i] & 0x08) != 0;
        ++i;
    }

    if (i >= MaxLength)
    {
        return 0;   // 只有前缀，没有操作码
    }

    std::uint8_t op = Code[i];
    ++i;

    //
    // VEX (C4/C5) / EVEX (62) 编码：不支持。
    //
    if (op == 0xC4 || op == 0xC5 || op == 0x62)
    {
        return 0;
    }

    bool hasModRM = false;
    std::uint32_t immSize = 0;
    std::uint32_t memOffs = 0;
    int f6f7Digit = -1;
    std::uint8_t opcode2 = 0;
    std::uint32_t kind = NPX_KIND_PLAIN;
    std::int32_t relDisp = 0;
    std::uint8_t relDispOff = 0;
    std::uint8_t relDispSize = 0;

    if (op == 0x0F)
    {
        //
        // 3a. 0F 双字节操作码（及 0F 38 / 0F 3A 三字节）
        //
        if (i >= MaxLength)
        {
            return 0;
        }
        opcode2 = Code[i];
        ++i;

        if (opcode2 == 0x38 || opcode2 == 0x3A)
        {
            if (i >= MaxLength)
            {
                return 0;
            }
            ++i;                            // 第三个操作码字节
            hasModRM = true;
            if (opcode2 == 0x3A)
            {
                immSize = 1;                // 0F 3A xx 全部带 imm8
            }
        }
        else
        {
            switch (opcode2)
            {
            // 无 ModRM、无立即数
            case 0x05:  // syscall
            case 0x06:  // clts
            case 0x07:  // sysret
            case 0x08:  // invd
            case 0x09:  // wbinvd
            case 0x0B:  // ud2
            case 0x0E:  // femms
            case 0x30:  // wrmsr
            case 0x31:  // rdtsc
            case 0x32:  // rdmsr
            case 0x33:  // rdpmc
            case 0x34:  // sysenter
            case 0x35:  // sysexit
            case 0x36:
            case 0x37:  // getsec
            case 0x77:  // emms
            case 0xA0:  // push fs
            case 0xA1:  // pop fs
            case 0xA2:  // cpuid
            case 0xA8:  // push gs
            case 0xA9:  // pop gs
            case 0xAA:  // rsm
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF: // bswap
                break;

            // 相对跳转 rel32
            case 0x80: case 0x81: case 0x82: case 0x83:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8C: case 0x8D: case 0x8E: case 0x8F:
                immSize = 4;
                kind = NPX_KIND_JCC_REL32;
                relDispOff = static_cast<std::uint8_t>(i);
                relDispSize = 4;
                break;

            // ModRM + imm8
            case 0x70:  // pshufw/pshufd
            case 0x71: case 0x72: case 0x73:    // 移位组
            case 0xA4:  // shld imm8
            case 0xAC:  // shrd imm8
            case 0xBA:  // bt/bts/btr/btc imm8
            case 0xC2:  // cmpps imm8
            case 0xC4:  // pinsrw imm8
            case 0xC5:  // pextrw imm8
            case 0xC6:  // shufps imm8
            case 0x0F:  // 3dnow imm8
                hasModRM = true;
                immSize = 1;
                break;

            // 其余 0F xx：ModRM、无立即数
            default:
                hasModRM = true;
                break;
            }
        }
    }
    else
    {
        //
        // 3b. 单字节操作码
        //
        switch (op)
        {
        // ---- ModRM、无立即数 ----
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x63:  // movsxd
        case 0x84: case 0x85:   // test
        case 0x86: case 0x87:   // xchg
        case 0x88: case 0x89: case 0x8A: case 0x8B: // mov
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: // mov sreg/lea/pop r/m
        case 0xD0: case 0xD1: case 0xD2: case 0xD3: // 移位/旋转
        case 0xFE: case 0xFF:   // group4/5
            hasModRM = true;
            break;

        // ---- AL, imm8 ----
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
            immSize = 1;
            break;

        // ---- AX/EAX/RAX, imm16/32 ----
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
            immSize = prefix66 ? 2 : 4;
            break;

        // 段寄存器操作，64 位模式非法
        case 0x06: case 0x07: case 0x0E: case 0x0F:
        case 0x16: case 0x17: case 0x1E: case 0x1F:
        case 0x26: case 0x27: case 0x2E: case 0x2F:
        case 0x36: case 0x37: case 0x3E: case 0x3F:
            return 0;

        // REX 后紧跟 REX（非法编码），按 INC r32 处理
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            break;

        // push/pop r64
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            break;

        // 64 位模式非法（0x62 可能是 EVEX，不支持）
        case 0x60: case 0x61: case 0x62:
        case 0x9A: case 0xCE: case 0xD6: case 0xEA:
            return 0;

        case 0x68:  // push imm16/32
            immSize = prefix66 ? 2 : 4;
            break;
        case 0x69:  // imul r/m, r/m, imm
            hasModRM = true;
            immSize = prefix66 ? 2 : 4;
            break;
        case 0x6A:  // push imm8
            immSize = 1;
            break;
        case 0x6B:  // imul r/m, r/m, imm8
            hasModRM = true;
            immSize = 1;
            break;

        case 0x6C: case 0x6D: case 0x6E: case 0x6F: // ins/outs
            break;

        // jcc rel8
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            immSize = 1;
            kind = NPX_KIND_JCC_REL8;
            relDispOff = static_cast<std::uint8_t>(i);
            relDispSize = 1;
            break;

        // group1（算术/逻辑 r/m, imm）
        case 0x80:
            hasModRM = true;
            immSize = 1;
            break;
        case 0x81:
            hasModRM = true;
            immSize = prefix66 ? 2 : 4;
            break;
        case 0x82:  // 64 位模式非法，按 80 处理
            hasModRM = true;
            immSize = 1;
            break;
        case 0x83:
            hasModRM = true;
            immSize = 1;
            break;

        case 0x90:  // nop
            break;
        case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97: // xchg r64, rax
            break;

        case 0x98: case 0x99:   // cwde/cdq
        case 0x9B:              // fwait
        case 0x9C: case 0x9D:   // pushf/popf
        case 0x9E: case 0x9F:   // sahf/lahf
            break;

        // mov moffs（绝对偏移，无需重定位）
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            memOffs = prefix67 ? 4 : 8;
            break;

        case 0xA4: case 0xA5: case 0xA6: case 0xA7: // movs/cmps
        case 0xAA: case 0xAB: case 0xAC: case 0xAD: // stos/lods
        case 0xAE: case 0xAF:                       // scas
            break;

        case 0xA8:  // test al, imm8
            immSize = 1;
            break;
        case 0xA9:  // test ax/eax, imm
            immSize = prefix66 ? 2 : 4;
            break;

        // mov r8, imm8
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            immSize = 1;
            break;

        // mov r64, imm
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            if (rexW)
            {
                immSize = 8;
            }
            else if (prefix66)
            {
                immSize = 2;
            }
            else
            {
                immSize = 4;
            }
            break;

        case 0xC0: case 0xC1:   // 移位 r/m, imm8
            hasModRM = true;
            immSize = 1;
            break;
        case 0xC2:              // ret imm16
            immSize = 2;
            break;
        case 0xC3:              // ret
            break;
        case 0xC6:              // mov r/m, imm8
            hasModRM = true;
            immSize = 1;
            break;
        case 0xC7:              // mov r/m, imm16/32
            hasModRM = true;
            immSize = prefix66 ? 2 : 4;
            break;
        case 0xC8:              // enter imm16, imm8
            immSize = 3;
            break;
        case 0xC9:              // leave
            break;
        case 0xCA:              // retf imm16
            immSize = 2;
            break;
        case 0xCB:              // retf
            break;
        case 0xCC:              // int3
            break;
        case 0xCD:              // int imm8
            immSize = 1;
            break;
        case 0xCF:              // iret
            break;

        case 0xD4: case 0xD5:   // aam/aad imm8
            immSize = 1;
            break;
        case 0xD7:              // xlat
            break;

        // x87 FPU
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            hasModRM = true;
            break;

        // loop/jcxz rel8（重定位器不支持 → 由重定位器拒绝）
        case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            immSize = 1;
            break;

        // in/out imm8
        case 0xE4: case 0xE5: case 0xE6: case 0xE7:
            immSize = 1;
            break;

        case 0xE8:              // call rel32
            immSize = 4;
            kind = NPX_KIND_CALL_REL32;
            relDispOff = static_cast<std::uint8_t>(i);
            relDispSize = 4;
            break;
        case 0xE9:              // jmp rel32
            immSize = 4;
            kind = NPX_KIND_JMP_REL32;
            relDispOff = static_cast<std::uint8_t>(i);
            relDispSize = 4;
            break;
        case 0xEB:              // jmp rel8
            immSize = 1;
            kind = NPX_KIND_JMP_REL8;
            relDispOff = static_cast<std::uint8_t>(i);
            relDispSize = 1;
            break;

        case 0xEC: case 0xED: case 0xEE: case 0xEF: // in/out dx
            break;

        case 0xF1:              // int1
            break;
        case 0xF4: case 0xF5:   // hlt/cmc
            break;
        case 0xF6:              // group3（TEST 才有立即数）
            hasModRM = true;
            f6f7Digit = 0;
            break;
        case 0xF7:
            hasModRM = true;
            f6f7Digit = 1;
            break;
        case 0xF8: case 0xF9:   // clc/stc
        case 0xFA: case 0xFB:   // cli/sti
        case 0xFC: case 0xFD:   // cld/std
            break;

        default:
            return 0;
        }
    }

    //
    // 4. ModRM / SIB / 位移
    //
    std::uint8_t modrm = 0;
    std::uint8_t modrmOff = 0;
    if (hasModRM)
    {
        if (i >= MaxLength)
        {
            return 0;
        }
        modrm = Code[i];
        modrmOff = static_cast<std::uint8_t>(i);
        std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6) & 3);
        std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3) & 7);
        std::uint8_t rm = static_cast<std::uint8_t>(modrm & 7);
        ++i;

        if (f6f7Digit >= 0)
        {
            // F6: digit 0/1 → imm8；F7: digit 0/1 → imm16/32
            if (reg <= 1)
            {
                immSize = (f6f7Digit == 0) ? 1 : (prefix66 ? 2 : 4);
            }
            else
            {
                immSize = 0;
            }
        }

        if (mod != 3)
        {
            if (rm == 4)
            {
                // SIB 字节
                if (i >= MaxLength)
                {
                    return 0;
                }
                std::uint8_t sib = Code[i];
                ++i;
                if (mod == 0 && (sib & 7) == 5)
                {
                    if (i + 4 > MaxLength)
                    {
                        return 0;
                    }
                    i += 4;     // disp32（无基址，非 RIP 相对）
                }
            }
            if (mod == 0 && rm == 5)
            {
                if (i + 4 > MaxLength)
                {
                    return 0;
                }
                if (prefixSeg == 0)
                {
                    //
                    // 无段前缀的 mod=00 rm=101 → RIP 相对 disp32
                    //
                    info.RipDispOff = static_cast<std::uint8_t>(i);
                    kind = NPX_KIND_RIP_RELATIVE;
                }
                i += 4;         // disp32
            }
            else if (mod == 1)
            {
                if (i + 1 > MaxLength)
                {
                    return 0;
                }
                i += 1;         // disp8
            }
            else if (mod == 2)
            {
                if (i + 4 > MaxLength)
                {
                    return 0;
                }
                i += 4;         // disp32
            }
        }
    }

    //
    // 5. moffs
    //
    if (memOffs != 0)
    {
        if (i + memOffs > MaxLength)
        {
            return 0;
        }
        i += memOffs;
    }

    //
    // 6. 立即数（同时提取相对位移值）
    //
    if (immSize != 0)
    {
        if (i + immSize > MaxLength)
        {
            return 0;
        }
        if (relDispSize != 0 && relDispOff != 0)
        {
            if (relDispSize == 1)
            {
                relDisp = static_cast<std::int8_t>(Code[relDispOff]);
            }
            else
            {
                relDisp = static_cast<std::int32_t>(
                    *reinterpret_cast<const std::int32_t*>(Code + relDispOff));
            }
        }
        i += immSize;
    }

    if (Out != nullptr)
    {
        info.Length = i;
        info.Kind = kind;
        info.Opcode = op;
        info.Opcode2 = opcode2;
        info.HasModRm = hasModRM ? 1 : 0;
        info.ModRm = modrm;
        info.ModRmOff = modrmOff;
        info.Rex = rex;
        info.RexW = rexW ? 1 : 0;
        info.Prefix66 = prefix66 ? 1 : 0;
        info.PrefixRep = prefixRep;
        info.PrefixLock = prefixLock;
        info.PrefixSeg = prefixSeg;
        info.RelDisp = relDisp;
        info.RelDispOff = relDispOff;
        info.RelDispSize = relDispSize;
        // RipDispOff 已在 ModRM 段填充
        *Out = info;
    }

    return i;
}

} // namespace

std::uint32_t
NpDisasmDecode(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MaxLength,
    _Out_opt_ NPX_INSN* Out)
{
    return NpDisasmDecodeCore(Code, MaxLength, Out);
}

std::uint32_t
GetInstructionLength(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MaxLength)
{
    return NpDisasmDecodeCore(Code, MaxLength, nullptr);
}

bool
GetPrologueLength(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MinLength,
    _Out_ std::uint32_t* OutLength)
{
    if (Code == nullptr || OutLength == nullptr || MinLength == 0)
    {
        return false;
    }

    std::uint32_t total = 0;
    while (total < MinLength)
    {
        std::uint32_t len = GetInstructionLength(Code + total, 15);
        if (len == 0)
        {
            return false;
        }
        total += len;
        if (total > 15)
        {
            return false;
        }
    }
    *OutLength = total;
    return true;
}

} // namespace NptHook
