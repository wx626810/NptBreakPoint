/*!
    @file       NpReloc.h

    @brief      克隆页重定位器：把 [原页 P][镜像 P+0x1000] 的字节拷贝
                重写为可在任意虚拟地址执行的位置无关代码。

    @details    方案C 的克隆块在池内存（CloneVA）执行，与原虚拟地址
                相差数 GB——所有相对跳转（call/jmp/jcc rel32/rel8）和
                RIP 相对内存引用（mov/lea/… [rip+disp]）都会算错目标。
                本模块扫描 8KB 源块，逐指令分类：
                - 目标仍在块内（同页/镜像页）→ 保持相对并修正位移；
                - 目标在块外（其他函数/全局数据）→ 改写为绝对寻址：
                    call/jmp rel → mov r11,imm64; call/jmp r11
                    jcc rel      → 反向短跳 + r11 跳板
                    rip-relative → mov <死寄存器>,imm64 + 内存指令重编码
                                    （lea 直接改 movabs）
                无暂存寄存器可用或遇到无法安全改写的指令时，返回失败
                ——调用方必须拒绝安装该 Hook（宁可失败不可错误）。

                纯逻辑（无 WDK 依赖），可在主机侧对 ntoskrnl 做离线验证。
  */
#pragma once

#include <cstdint>
#include <sal.h>

namespace NptHook
{

#define NP_RELOC_BLOCK_SIZE     0x2000   // 源块 = 2 页：[P][P+0x1000 镜像]
#define NP_RELOC_MAX_OUT        0x4000   // 重定位输出上限（4 页）
#define NP_RELOC_MAX_ENTRIES    4096     // 偏移映射表条目上限

// 代码区间（块内偏移，[Beg, End)）：仅区间内按代码重定位，
// 区间外（跳转表/对齐/填充数据）原样复制，绝不解码。
typedef struct _NP_RELOC_RANGE
{
    std::uint32_t Beg;
    std::uint32_t End;
} NP_RELOC_RANGE;

// 偏移映射表条目（OrigOff 升序；NewOff 单调不减）。
// Map(off) = 最后一个 OrigOff<=off 条目的 NewOff + (off - OrigOff)。
typedef struct _NP_RELOC_MAP
{
    std::uint32_t OrigOff;
    std::uint32_t NewOff;
} NP_RELOC_MAP;

typedef struct _NP_RELOC_RESULT
{
    std::uint32_t OutLen;        // 重定位后代码长度（字节）
    std::uint32_t MapCount;      // 映射表条目数
    NP_RELOC_MAP* Map;           // 调用方提供的映射缓冲
    std::uint32_t MapCapacity;   // 映射缓冲条目容量
    std::uint32_t FailKind;      // 失败类别（0=成功；1=解码失败；2=映射容量；
                                 //   3=无暂存寄存器；4=不支持的 RIP 形式；
                                 //   5=区间非法；6=输出容量）
    std::uint32_t FailOff;       // 失败指令的块内偏移
} NP_RELOC_RESULT;

// 对 8KB 克隆源块执行重定位。
//
// @param[in]  SrcBlock   - 源块（8KB：[P 拷贝][P+0x1000 镜像]）。
// @param[in]  OrigPageVa - 源块第 0 页对应的真实内核 VA（页对齐）。
// @param[in]  FuncEntryOff - 函数入口在块内偏移（诊断用）。
// @param[in]  Ranges     - 代码区间数组（块内偏移，升序、不相交）。
// @param[in]  RangeCount - 区间数。
// @param[out] OutBuf     - 输出缓冲（容量 OutCap）。
// @param[in]  OutCap     - 输出容量（建议 NP_RELOC_MAX_OUT）。
// @param[out] Result     - 结果（含映射表，Map 缓冲由调用方提供）。
//
// @return     true 成功；false 失败（遇到不可安全重写的指令/容量不足/
//             无可用暂存寄存器）——调用方必须拒绝安装该 Hook。
//
bool NpRelocRelocateBlock(
    _In_ const std::uint8_t* SrcBlock,
    _In_ std::uintptr_t OrigPageVa,
    _In_ std::uint32_t FuncEntryOff,
    _In_reads_opt_(RangeCount) const NP_RELOC_RANGE* Ranges,
    _In_ std::uint32_t RangeCount,
    _Out_writes_(OutCap) std::uint8_t* OutBuf,
    _In_ std::uint32_t OutCap,
    _Out_ NP_RELOC_RESULT* Result);

// 通过映射表把原始偏移换算为重定位后偏移。
std::uint32_t NpRelocMapLookup(
    _In_ const NP_RELOC_MAP* Map,
    _In_ std::uint32_t MapCount,
    _In_ std::uint32_t Off);

} // namespace NptHook
