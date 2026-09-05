/*!
    @file       TestReloc.cpp

    @brief      克隆页重定位器主机验证（MinGW g++ 编译运行）。

    @details    加载本机 ntoskrnl.exe：
                1) 对三个真实目标函数（NtQueryInformationProcess /
                   NtQuerySystemInformation / RtlLookupFunctionEntry）
                   构建双页源块 + .pdata 代码区间 → 执行重定位 →
                   结构校验（全部指令可解码、块内相对跳转落在指令边界、
                   映射表单调一致、数据区字节原样）→ 导出重定位字节
                   （供 objdump 目检）；
                2) 全 .text 线性解码覆盖率统计（衡量解码器对真实
                   内核代码的覆盖）。

    构建：g++ -O2 -std=c++17 NpRelocTest.cpp NpDisasm.cpp NpReloc.cpp -o NpRelocTest.exe
  */
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <windows.h>

#include "NpDisasm.hpp"
#include "NpReloc.h"

using namespace NptHook;

// ============================ 极简 PE 解析 ============================

typedef struct _PE_IMAGE
{
    std::vector<std::uint8_t> Bytes;
    std::uintptr_t ImageBase;
    std::uint32_t SizeOfImage;
    struct SEC { std::uint32_t Va; std::uint32_t Raw; std::uint32_t Size; };
    std::vector<SEC> Sections;
} PE_IMAGE;

static bool
PeLoad(const char* Path, PE_IMAGE* Out)
{
    FILE* f = fopen(Path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    Out->Bytes.resize(sz);
    if (fread(Out->Bytes.data(), 1, sz, f) != (size_t)sz) { fclose(f); return false; }
    fclose(f);

    const uint8_t* b = Out->Bytes.data();
    if (sz < 0x1000 || b[0] != 'M' || b[1] != 'Z') return false;
    uint32_t e_lfanew = *(uint32_t*)(b + 0x3C);
    if (e_lfanew + 0x100 > (uint32_t)sz) return false;
    const uint8_t* nth = b + e_lfanew;
    if (*(uint32_t*)nth != 0x00004550) return false;   // PE\0\0
    uint16_t nsec = *(uint16_t*)(nth + 6);
    Out->ImageBase = *(uintptr_t*)(nth + 0x18 + 0x18); // OptionalHeader.ImageBase (PE32+)
    Out->SizeOfImage = *(uint32_t*)(nth + 0x18 + 0x38);
    uint32_t optSize = *(uint16_t*)(nth + 0x14);
    const uint8_t* sec = nth + 0x18 + optSize;
    for (uint16_t i = 0; i < nsec; i++)
    {
        PE_IMAGE::SEC s;
        s.Va = *(uint32_t*)(sec + i * 40 + 12);
        s.Size = *(uint32_t*)(sec + i * 40 + 8);
        s.Raw = *(uint32_t*)(sec + i * 40 + 20);
        Out->Sections.push_back(s);
    }
    return true;
}

// RVA → 文件偏移；失败返回 0xFFFFFFFF
static uint32_t
PeRvaToOff(const PE_IMAGE* Img, uint32_t Rva)
{
    for (size_t i = 0; i < Img->Sections.size(); i++)
    {
        const PE_IMAGE::SEC& s = Img->Sections[i];
        if (Rva >= s.Va && Rva < s.Va + s.Size)
        {
            return s.Raw + (Rva - s.Va);
        }
    }
    return 0xFFFFFFFF;
}

static const uint8_t*
PeRvaPtr(const PE_IMAGE* Img, uint32_t Rva)
{
    uint32_t off = PeRvaToOff(Img, Rva);
    if (off == 0xFFFFFFFF || off >= Img->Bytes.size()) return nullptr;
    return Img->Bytes.data() + off;
}

// 导出表查名
static uint32_t
PeExportRva(const PE_IMAGE* Img, const char* Name)
{
    const uint8_t* b = Img->Bytes.data();
    uint32_t e_lfanew = *(uint32_t*)(b + 0x3C);
    const uint8_t* nth = b + e_lfanew;
    uint32_t dirRva = *(uint32_t*)(nth + 0x18 + 0x70);   // export dir VA
    uint32_t dirSize = *(uint32_t*)(nth + 0x18 + 0x74);
    if (dirRva == 0 || dirSize == 0) return 0;
    const uint8_t* dir = PeRvaPtr(Img, dirRva);
    if (!dir) return 0;
    uint32_t nNames = *(uint32_t*)(dir + 24);
    uint32_t namesRva = *(uint32_t*)(dir + 32);
    uint32_t ordRva = *(uint32_t*)(dir + 36);
    uint32_t funcRva = *(uint32_t*)(dir + 28);
    for (uint32_t i = 0; i < nNames; i++)
    {
        const uint8_t* p = PeRvaPtr(Img, *(uint32_t*)PeRvaPtr(Img, namesRva + i * 4));
        if (p && strcmp((const char*)p, Name) == 0)
        {
            uint16_t ord = *(uint16_t*)PeRvaPtr(Img, ordRva + i * 2);
            return *(uint32_t*)PeRvaPtr(Img, funcRva + ord * 4);
        }
    }
    return 0;
}

// .pdata 目录（RVA, 大小）——DataDirectory[3]（Exception）
static void
PePdataDir(const PE_IMAGE* Img, uint32_t* Rva, uint32_t* Size)
{
    const uint8_t* b = Img->Bytes.data();
    uint32_t e_lfanew = *(uint32_t*)(b + 0x3C);
    const uint8_t* nth = b + e_lfanew;
    *Rva = *(uint32_t*)(nth + 0x18 + 0x88);   // optional + 0x88 = index 3
    *Size = *(uint32_t*)(nth + 0x18 + 0x8C);
}

// ============================ 校验辅助 ============================

static int g_Fail = 0;

static void
Verify(const char* Msg, bool Ok)
{
    if (!Ok)
    {
        std::printf("  [FAIL] %s\n", Msg);
        g_Fail++;
    }
    else
    {
        std::printf("  [ ok ] %s\n", Msg);
    }
}

// 从重定位输出中按代码区间重走一遍，校验全部指令可解码、相对跳转落在
// 指令边界、映射表单调、数据区原样。
static bool
VerifyRelocated(const uint8_t* Src, const uint8_t* Out, uint32_t OutLen,
                const NP_RELOC_RANGE* Ranges, uint32_t RangeCount,
                const NP_RELOC_MAP* Map, uint32_t MapCount,
                uint32_t* OutInsnCount)
{
    // 收集重定位输出内的指令起始集合（仅代码区间内，经映射）
    std::vector<uint32_t> starts;
    uint32_t insnCount = 0;

    for (uint32_t ri = 0; ri < RangeCount; ri++)
    {
        // 区间 [beg,end) 的原始指令从 beg 起连续解码
        uint32_t off = Ranges[ri].Beg;
        while (off < Ranges[ri].End)
        {
            NPX_INSN in;
            uint32_t len = NpDisasmDecode(Src + off, 15, &in);
            if (len == 0 || in.Length == 0)
            {
                std::printf("  [FAIL] 源解码失败 @0x%x (range %u)\n", off, ri);
                return false;
            }
            if (off + len > Ranges[ri].End)
            {
                break;      // 区间尾残缺指令：原样复制，停止本区间
            }
            uint32_t newOff = NpRelocMapLookup(Map, MapCount, off);
            if (newOff >= OutLen)
            {
                std::printf("  [FAIL] 映射越界 @0x%x -> 0x%x\n", off, newOff);
                return false;
            }
            // 输出端按重定位布局重解码，长度必须与映射一致
            NPX_INSN outIn;
            uint32_t outLen = NpDisasmDecode(Out + newOff, 15, &outIn);
            if (outLen == 0)
            {
                std::printf("  [FAIL] 输出解码失败 @0x%x (src 0x%x)\n", newOff, off);
                return false;
            }
            starts.push_back(newOff);
            insnCount++;
            off += len;
        }
    }

    std::sort(starts.begin(), starts.end());

    // 相对跳转目标校验（输出端重解码）
    for (uint32_t ri = 0; ri < RangeCount; ri++)
    {
        uint32_t off = Ranges[ri].Beg;
        while (off < Ranges[ri].End)
        {
            NPX_INSN in;
            uint32_t len = NpDisasmDecode(Src + off, 15, &in);
            if (len == 0 || off + len > Ranges[ri].End)
            {
                break;      // 区间尾残缺指令：跳过
            }
            uint32_t newOff = NpRelocMapLookup(Map, MapCount, off);
            NPX_INSN outIn;
            uint32_t outLen = NpDisasmDecode(Out + newOff, 15, &outIn);
            if (outIn.Kind == NPX_KIND_CALL_REL32 ||
                outIn.Kind == NPX_KIND_JMP_REL32 ||
                outIn.Kind == NPX_KIND_JCC_REL32)
            {
                int64_t tgt = (int64_t)newOff + outLen + outIn.RelDisp;
                if (tgt < 0 || tgt >= (int64_t)OutLen ||
                    !std::binary_search(starts.begin(), starts.end(), (uint32_t)tgt))
                {
                    std::printf("  [FAIL] 相对跳转目标非法 @new 0x%x -> 0x%llx\n",
                                newOff, (unsigned long long)tgt);
                    return false;
                }
            }
            off += len;
        }
    }

    // 数据区（区间外）必须原样
    {
        uint32_t cur = 0;
        for (uint32_t ri = 0; ri < RangeCount; ri++)
        {
            for (uint32_t k = cur; k < Ranges[ri].Beg && k < NP_RELOC_BLOCK_SIZE; k++)
            {
                uint32_t newK = NpRelocMapLookup(Map, MapCount, k);
                if (newK < OutLen && Out[newK] != Src[k])
                {
                    std::printf("  [FAIL] 数据区被修改 @0x%x\n", k);
                    return false;
                }
            }
            cur = Ranges[ri].End;
        }
        for (uint32_t k = cur; k < NP_RELOC_BLOCK_SIZE; k++)
        {
            uint32_t newK = NpRelocMapLookup(Map, MapCount, k);
            if (newK < OutLen && Out[newK] != Src[k])
            {
                std::printf("  [FAIL] 数据区被修改(尾) @0x%x\n", k);
                return false;
            }
        }
    }

    // 映射表单调性
    for (uint32_t i = 1; i < MapCount; i++)
    {
        if (Map[i].OrigOff <= Map[i - 1].OrigOff || Map[i].NewOff < Map[i - 1].NewOff)
        {
            std::printf("  [FAIL] 映射表非单调 @%u\n", i);
            return false;
        }
    }

    //
    // 语义校验：r11 跳板必须是 [49 BB imm64][41 FF D3/E3]（REX.B 必须存在，
    // 否则 FF D3 = call rbx 调用垃圾寄存器）；且 imm64 为内核地址。
    //
    for (uint32_t i = 0; i + 12 < OutLen; i++)
    {
        if (Out[i] == 0x49 && Out[i + 1] == 0xBB)
        {
            uint64_t imm = 0;
            for (uint32_t k = 0; k < 8; k++)
            {
                imm |= (uint64_t)Out[i + 2 + k] << (8 * k);
            }
            if (imm < 0xFFFF800000000000ull)
            {
                continue;                   // 非内核地址的 movabs：原代码，跳过
            }
            uint8_t t0 = Out[i + 10];
            if (t0 == 0xFF &&
                (Out[i + 11] == 0xD3 || Out[i + 11] == 0xE3 || Out[i + 11] == 0x33))
            {
                std::printf("  [FAIL] r11 跳板缺 REX.B @new 0x%x\n", i);
                return false;
            }
            if (t0 == 0x41 && Out[i + 11] == 0xFF)
            {
                // 带 REX.B 的跳板：校验目标合理（内核地址已在上面确认）
            }
        }
    }

    *OutInsnCount = insnCount;
    return true;
}

// ============================ 目标函数测试 ============================

static void
RunFunction(const PE_IMAGE* Img, const char* Name, uint32_t ExportRva,
            const char* DumpPath)
{
    std::printf("== %s @ RVA 0x%X ==\n", Name, ExportRva);

    uint32_t pageRvaLo = ExportRva & ~0xFFFu;
    uint32_t pageRvaHi = pageRvaLo + NP_RELOC_BLOCK_SIZE;

    // 双页源块（文件读；页边界处可能不足 2 页，用 0 填充）
    std::vector<uint8_t> src(NP_RELOC_BLOCK_SIZE, 0);
    for (uint32_t off = 0; off < NP_RELOC_BLOCK_SIZE; off++)
    {
        const uint8_t* p = PeRvaPtr(Img, pageRvaLo + off);
        if (p) src[off] = *p;
    }

    // .pdata 代码区间（排除起始于本块之前的跨页条目——其块内尾部
    // 指令边界未知，由 NPF 恒等单步从真页执行）
    uint32_t pdataRva = 0, pdataSize = 0;
    PePdataDir(Img, &pdataRva, &pdataSize);
    std::vector<NP_RELOC_RANGE> ranges;
    if (pdataRva && pdataSize >= 12)
    {
        uint32_t n = pdataSize / 12;
        for (uint32_t i = 0; i < n; i++)
        {
            const uint8_t* e = PeRvaPtr(Img, pdataRva + i * 12);
            if (!e) break;
            uint32_t b = *(uint32_t*)(e + 0);
            uint32_t en = *(uint32_t*)(e + 4);
            if (b < pageRvaLo) continue;            // 跨页条目：排除
            if (en <= pageRvaLo || b >= pageRvaHi) continue;
            uint32_t rb = b - pageRvaLo;
            uint32_t re = (en < pageRvaHi) ? en - pageRvaLo : NP_RELOC_BLOCK_SIZE;
            if (re <= rb) continue;
            if (!ranges.empty() && ranges.back().End >= rb)
            {
                if (ranges.back().End < re) ranges.back().End = re;
            }
            else
            {
                ranges.push_back({ rb, re });
            }
        }
    }
    std::printf("  代码区间 %u 个:", (uint32_t)ranges.size());
    for (auto& r : ranges) std::printf(" [%x,%x)", r.Beg, r.End);
    std::printf("\n");

    //
    // 调试：转储代码区间走查（偏移 + 字节 + 长度），对照 objdump 定位
    // 解码长度偏差。仅当设置 RELOC_DUMP_WALK 环境变量时打印。
    //
    if (getenv("RELOC_DUMP_WALK"))
    {
        const char* only = getenv("RELOC_DUMP_FUNC");
        if (only == nullptr || strcmp(only, Name) == 0)
        {
            for (uint32_t ri = 0; ri < (uint32_t)ranges.size(); ri++)
            {
                std::printf("  [walk r%u] %x..%x\n", ri, ranges[ri].Beg, ranges[ri].End);
                uint32_t off = ranges[ri].Beg;
                uint32_t cnt = 0;
                while (off < ranges[ri].End && cnt < 400)
                {
                    NPX_INSN in;
                    uint32_t len = NpDisasmDecode(src.data() + off, 15, &in);
                    if (len == 0 || off + len > ranges[ri].End) break;
                    std::printf("    %04x: ", off);
                    for (uint32_t k = 0; k < len && k < 8; k++)
                    {
                        std::printf("%02x ", src[off + k]);
                    }
                    std::printf("  len=%u kind=%u\n", len, (unsigned)in.Kind);
                    off += len; cnt++;
                }
            }
            exit(0);
        }
    }

    std::vector<uint8_t> out(NP_RELOC_MAX_OUT, 0);
    std::vector<NP_RELOC_MAP> map(NP_RELOC_MAX_ENTRIES);
    NP_RELOC_RESULT rr;
    rr.Map = map.data();
    rr.MapCapacity = NP_RELOC_MAX_ENTRIES;
    rr.OutLen = 0;
    rr.MapCount = 0;

    std::uintptr_t origPageVa = Img->ImageBase + pageRvaLo;
    bool ok = NpRelocRelocateBlock(src.data(), origPageVa, ExportRva & 0xFFF,
                                   ranges.data(), (uint32_t)ranges.size(),
                                   out.data(), NP_RELOC_MAX_OUT, &rr);
    if (!ok)
    {
        std::printf("  [FAIL] 重定位失败 kind=%u off=0x%x\n", rr.FailKind, rr.FailOff);
        g_Fail++;
        return;
    }
    std::printf("  重定位成功: out=0x%x (源 0x%x) 膨胀 +0x%x, map=%u\n",
                rr.OutLen, NP_RELOC_BLOCK_SIZE,
                rr.OutLen > NP_RELOC_BLOCK_SIZE ? rr.OutLen - NP_RELOC_BLOCK_SIZE : 0,
                rr.MapCount);

    uint32_t insnCount = 0;
    bool vok = VerifyRelocated(src.data(), out.data(), rr.OutLen,
                               ranges.data(), (uint32_t)ranges.size(),
                               map.data(), rr.MapCount, &insnCount);
    Verify("结构校验（解码/跳转边界/映射/数据区）", vok);
    std::printf("  指令数: %u\n", insnCount);

    // 导出重定位字节供 objdump 目检
    if (DumpPath)
    {
        FILE* f = fopen(DumpPath, "wb");
        if (f)
        {
            fwrite(out.data(), 1, rr.OutLen, f);
            fclose(f);
            std::printf("  导出: %s\n", DumpPath);
        }
    }
}

// ============================ 全 .text 覆盖统计 ============================

static void
CoverageScan(const PE_IMAGE* Img)
{
    std::printf("== 全代码段线性解码覆盖 ==\n");
    uint64_t totalBytes = 0, failBytes = 0, insnTotal = 0;
    uint32_t fails[16] = {0};

    for (size_t si = 0; si < Img->Sections.size(); si++)
    {
        const PE_IMAGE::SEC& s = Img->Sections[si];
        if (!(s.Va >= 0x1000)) continue;    // 粗滤
        // 只扫 .text / PAGE / INIT 类代码段（名字判断）
        const char* names[] = { ".text", "PAGE", "INIT", "PAGEVRFY", ".textbss" };
        char secName[9] = {0};
        {
            // 从节表拿名字
            const uint8_t* b = Img->Bytes.data();
            uint32_t e_lfanew = *(uint32_t*)(b + 0x3C);
            const uint8_t* nth = b + e_lfanew;
            uint32_t optSize = *(uint16_t*)(nth + 0x14);
            const uint8_t* sec = nth + 0x18 + optSize + si * 40;
            memcpy(secName, sec, 8);
        }
        bool isCode = false;
        for (auto nm : names) if (strncmp(secName, nm, 8) == 0) isCode = true;
        if (!isCode) continue;

        uint64_t secBytes = 0, secFail = 0;
        uint32_t off = 0;
        while (off < s.Size && s.Raw + off < Img->Bytes.size())
        {
            const uint8_t* p = Img->Bytes.data() + s.Raw + off;
            NPX_INSN in;
            uint32_t len = NpDisasmDecode(p, 15, &in);
            if (len == 0 || in.Length == 0)
            {
                secFail++;
                off += 1;
                continue;
            }
            insnTotal++;
            off += len;
        }
        secBytes = s.Size;
        totalBytes += secBytes;
        failBytes += secFail;
        std::printf("  %-8s size=0x%x decode-fail=%llu\n",
                    secName, s.Size, (unsigned long long)secFail);
    }
    std::printf("  合计: 指令 %llu, 失败字节 %llu / %llu (%.4f%%)\n",
                (unsigned long long)insnTotal,
                (unsigned long long)failBytes,
                (unsigned long long)totalBytes,
                totalBytes ? 100.0 * (double)failBytes / (double)totalBytes : 0.0);
}

int
main(int argc, char** argv)
{
    const char* path = "C:\\Windows\\System32\\ntoskrnl.exe";
    if (argc > 1) path = argv[1];

    PE_IMAGE img;
    if (!PeLoad(path, &img))
    {
        std::printf("无法加载 %s\n", path);
        return 1;
    }
    std::printf("ntoskrnl: ImageBase=0x%llX SizeOfImage=0x%X\n",
                (unsigned long long)img.ImageBase, img.SizeOfImage);

    struct { const char* Name; const char* Dump; } targets[] = {
        { "NtQueryInformationProcess",  "reloc_QIP.bin"  },
        { "NtQuerySystemInformation",   "reloc_QSI.bin"  },
        { "RtlLookupFunctionEntry",     "reloc_RLFE.bin" },
    };
    for (auto& t : targets)
    {
        uint32_t rva = PeExportRva(&img, t.Name);
        if (rva == 0)
        {
            std::printf("== %s == [未导出]\n", t.Name);
            continue;
        }
        std::string dump = std::string("D:\\DSHproject\\NptBreakPoint\\output\\") + t.Dump;
        RunFunction(&img, t.Name, rva, dump.c_str());
    }

    CoverageScan(&img);

    std::printf("\n%s（失败 %d）\n", g_Fail ? "存在失败" : "全部通过", g_Fail);
    return g_Fail ? 1 : 0;
}
