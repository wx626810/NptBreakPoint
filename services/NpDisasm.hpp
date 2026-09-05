/*!
    @file       NpDisasm.hpp

    @brief      x64 指令长度解码器 + 指令分类（纯逻辑，WDK 无关）。
                供克隆页重定位器（NpReloc）识别相对跳转 / RIP 相对内存
                引用，也供 Hook 安装计算序言长度。
 */
#pragma once

#include <cstdint>
#include <sal.h>

namespace NptHook
{

// 指令分类（相对跳转 / RIP 相对内存引用）
#define NPX_KIND_PLAIN          0   // 无相对目标、无 rip-relative 操作数
#define NPX_KIND_CALL_REL32     1   // E8 cd
#define NPX_KIND_JMP_REL32      2   // E9 cd
#define NPX_KIND_JMP_REL8       3   // EB cb
#define NPX_KIND_JCC_REL8       4   // 70..7F cb
#define NPX_KIND_JCC_REL32      5   // 0F 80..8F cd
#define NPX_KIND_RIP_RELATIVE   6   // 含 RIP 相对内存操作数（mod=00 rm=101，无段前缀）

// 指令解码结果
typedef struct _NPX_INSN
{
    std::uint32_t Length;       // 指令总长度
    std::uint32_t Kind;         // NPX_KIND_*
    std::uint8_t  Opcode;       // 主操作码字节
    std::uint8_t  Opcode2;      // 0F 第二字节（主操作码非 0F 时为 0）
    std::uint8_t  HasModRm;     // 是否含 ModRM
    std::uint8_t  ModRm;        // ModRM 字节（HasModRm=0 时无意义）
    std::uint8_t  ModRmOff;     // ModRM 在指令内的偏移
    std::uint8_t  Rex;          // REX 前缀字节（0 = 无）
    std::uint8_t  RexW;         // REX.W
    std::uint8_t  Prefix66;     // 66 操作数宽度前缀
    std::uint8_t  PrefixRep;    // F2/F3 前缀（0 = 无；movsd/movss 等）
    std::uint8_t  PrefixLock;   // F0 lock 前缀（0 = 无）
    std::uint8_t  PrefixSeg;    // 段覆盖前缀（0=无；fs/gs 等存在时 rm=101 不是 RIP 相对）
    std::int32_t  RelDisp;      // 相对位移（符号扩展；仅相对跳转类）
    std::uint8_t  RelDispOff;   // 位移字段在指令内的偏移
    std::uint8_t  RelDispSize;  // 位移宽度（1 或 4；0 = 无）
    std::uint8_t  RipDispOff;   // RIP 相对 disp32 字段在指令内的偏移（0 = 无）
} NPX_INSN;

// 解码一条指令（长度 + 分类）。
//
// @param[in]  Code       - 指令字节流（至少 MaxLength 字节可读）。
// @param[in]  MaxLength  - 允许的最大长度（钳制到 15）。
// @param[out] Out        - 解码结果（可为 nullptr，仅求长度）。
//
// @return     指令长度；0 表示解码失败（未知/非法/VEX 编码）。
//
std::uint32_t NpDisasmDecode(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MaxLength,
    _Out_opt_ NPX_INSN* Out);

// 解码一条指令的长度（兼容旧接口，等价于 NpDisasmDecode 只取长度）。
std::uint32_t GetInstructionLength(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MaxLength = 15);

// 从 Code 起始处连续解码，直到累计长度 >= MinLength 且落在指令边界上。
bool GetPrologueLength(
    _In_ const std::uint8_t* Code,
    _In_ std::uint32_t MinLength,
    _Out_ std::uint32_t* OutLength);

} // namespace NptHook
