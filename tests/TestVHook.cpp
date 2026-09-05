/*!
    @file       TestVHook.cpp

    @brief      P4：NpVHook Cave 构建宿主验证。

    @details    与内核 NpVHook::BuildCave 同构（共用 NpDisasm/NpReloc）：
                1. 合成一个目标函数字节流（含短跳转/返回）；
                2. 计算入口序言长度（至少覆盖补丁长度）；
                3. 重定位剩余块为位置无关代码；
                4. 组装 Cave = [PatchCode][剩余块][mov rax,imm64; jmp rax]；
                5. 校验结构：前缀、指令边界、跳回目标 = 入口+序言长度。

    构建：g++ -O2 -std=c++17 TestVHook.cpp NpDisasm.cpp NpReloc.cpp -o TestVHook.exe
  */
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#include "NpDisasm.hpp"
#include "NpReloc.h"

using namespace NptHook;

static int g_Fail = 0;

static void Check(bool ok, const char* what)
{
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_Fail++;
}

int main()
{
    //
    // 合成目标函数（HookPoint 之后含一个条件跳转，验证重定位）：
    //   0: 48 83 EC 28        sub rsp, 0x28
    //   4: 8B 01              mov eax, [rcx]
    //   6: 83 C0 01           add eax, 1
    //   9: 83 F8 64           cmp eax, 0x64
    //   c: 7C 03              jl +3  (11)
    //   e: B8 00 00 00 00     mov eax, 0
    //  13: 48 83 C4 28        add rsp, 0x28
    //  17: C3                 ret
    //
    static const uint8_t kFunc[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x8B, 0x01,
        0x83, 0xC0, 0x01,
        0x83, 0xF8, 0x64,
        0x7C, 0x03,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
    };
    const uint32_t kHookOff = 0;                 // 入口 Hook
    const uint32_t kPatchLen = 5;                // 补丁覆盖 ≥5 字节
    const uintptr_t kPageVa = 0x140000000ULL;    // 模拟页基址（页对齐）

    // 8KB 源块（[P][P+0x1000]）：把函数放进第 0 页。
    std::vector<uint8_t> src(NP_RELOC_BLOCK_SIZE, 0x90);
    memcpy(src.data() + kHookOff, kFunc, sizeof(kFunc));

    // 1. 序言长度。
    uint32_t prolog = 0;
    bool ok = GetPrologueLength(src.data() + kHookOff, kPatchLen, &prolog);
    Check(ok && prolog >= kPatchLen && prolog == 6, "prologue length >= patch len");
    if (!ok) return 1;

    // 2. 重定位剩余块 [HookOff+Prolog .. 块尾)。
    std::vector<uint8_t> reloc(NP_RELOC_MAX_OUT);
    NP_RELOC_MAP map[NP_RELOC_MAX_ENTRIES];
    NP_RELOC_RESULT res;
    memset(&res, 0, sizeof(res));
    res.Map = map;
    res.MapCapacity = NP_RELOC_MAX_ENTRIES;
    NP_RELOC_RANGE range;
    range.Beg = kHookOff + prolog;
    range.End = NP_RELOC_BLOCK_SIZE;
    bool relocOk = NpRelocRelocateBlock(src.data(), kPageVa, kHookOff,
                                        &range, 1, reloc.data(),
                                        (uint32_t)reloc.size(), &res);
    Check(relocOk && res.OutLen > 0, "remainder relocated");
    if (!relocOk) return 1;

    // 3. 组装 Cave。
    static const uint8_t kPatch[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00 };  // mov eax, 42
    std::vector<uint8_t> cave;
    cave.insert(cave.end(), kPatch, kPatch + kPatchLen);
    cave.insert(cave.end(), reloc.begin(), reloc.begin() + res.OutLen);
    // 跳回桩
    uint64_t retAddr = kPageVa + kHookOff + prolog;
    cave.push_back(0x48); cave.push_back(0xB8);
    for (int i = 0; i < 8; i++) cave.push_back((uint8_t)(retAddr >> (8 * i)));
    cave.push_back(0xFF); cave.push_back(0xE0);

    // 4. 结构校验。
    Check(memcmp(cave.data(), kPatch, kPatchLen) == 0, "cave prefix = patch code");
    Check(cave[kPatchLen] != 0x90 || res.OutLen == 0, "remainder appended");
    Check(cave.size() >= 12 &&
          cave[cave.size() - 12] == 0x48 && cave[cave.size() - 11] == 0xB8 &&
          cave[cave.size() - 2] == 0xFF && cave[cave.size() - 1] == 0xE0,
          "jump-back stub present");
    uint64_t stubTarget = 0;
    for (int i = 0; i < 8; i++)
        stubTarget |= (uint64_t)cave[cave.size() - 10 + i] << (8 * i);
    Check(stubTarget == retAddr, "jump-back target = entry + prologue");

    // 5. 剩余块逐指令解码（验证没有 0 长度/非法）。
    bool allDecode = true;
    for (uint32_t off = 0; off < res.OutLen; )
    {
        uint32_t len = GetInstructionLength(cave.data() + kPatchLen + off,
                                            res.OutLen - off);
        if (len == 0) { allDecode = false; break; }
        off += len;
    }
    Check(allDecode, "remainder fully decodable");

    std::printf("\nRESULT: %s\n", g_Fail == 0 ? "ALL PASSED" : "FAILED");
    return g_Fail == 0 ? 0 : 1;
}
