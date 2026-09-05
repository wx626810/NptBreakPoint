/*!
    @file       TestSyscall.cpp

    @brief      P0：syscall 号/SSDT 离线跨版本预检（主机环境）。

    @details    直接加载目标机的 ntoskrnl.exe + ntdll.dll 文件，执行与
                NpSyscall（内核版）同算法的预检：
                1. ntdll stub 提取 7 项 syscall 号（QIP/QSI/RLFE + WVM/
                   RVM/DAP/SCT；RLFE 应为非 syscall）；
    2. ntoskrnl 导出表解析 QIP/QSI 地址（Nt 或 Zw 任一）；
                3. 双锚点 + 表特征扫描定位 KiServiceTable（4B/8B 变体）；
                4. 按 syscall 号回读表条目并与导出地址交叉比对；
                5. 未导出（Win11 24H2+）时给出明确降级结论。

    构建：g++ -O2 -std=c++17 TestSyscall.cpp -o TestSyscall.exe
    用法：TestSyscall.exe <ntoskrnl.exe> <ntdll.dll>
  */
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

typedef std::uint8_t u8;
typedef std::uint16_t u16;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
typedef std::int64_t i64;
typedef std::int32_t i32;

struct PE_IMAGE
{
    std::vector<u8> Bytes;
    u64 ImageBase;
    u32 SizeOfImage;
    struct SEC { u32 Va; u32 Raw; u32 Size; };
    std::vector<SEC> Sections;
};

static bool PeLoad(const char* Path, PE_IMAGE* Out)
{
    FILE* f = fopen(Path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0x1000) { fclose(f); return false; }
    Out->Bytes.resize((size_t)sz);
    if (fread(Out->Bytes.data(), 1, (size_t)sz, f) != (size_t)sz)
    { fclose(f); return false; }
    fclose(f);
    const u8* b = Out->Bytes.data();
    if (b[0] != 'M' || b[1] != 'Z') return false;
    u32 e = *(u32*)(b + 0x3C);
    if (e + 0x100 > (u32)sz) return false;
    if (*(u32*)(b + e) != 0x00004550) return false;
    u16 nsec = *(u16*)(b + e + 6);
    u16 optSize = *(u16*)(b + e + 0x14);
    Out->ImageBase = *(u64*)(b + e + 0x18 + 0x18);
    Out->SizeOfImage = *(u32*)(b + e + 0x18 + 0x38);
    const u8* sec = b + e + 0x18 + optSize;
    for (u16 i = 0; i < nsec; i++)
    {
        PE_IMAGE::SEC s;
        s.Va = *(u32*)(sec + i * 40 + 12);
        s.Size = *(u32*)(sec + i * 40 + 8);
        s.Raw = *(u32*)(sec + i * 40 + 20);
        Out->Sections.push_back(s);
    }
    return true;
}

static u32 PeRvaToOff(const PE_IMAGE* Img, u32 Rva)
{
    for (size_t i = 0; i < Img->Sections.size(); i++)
    {
        const PE_IMAGE::SEC& s = Img->Sections[i];
        if (Rva >= s.Va && Rva < s.Va + s.Size) return s.Raw + (Rva - s.Va);
    }
    return 0xFFFFFFFF;
}

static const u8* PeRvaPtr(const PE_IMAGE* Img, u32 Rva)
{
    u32 off = PeRvaToOff(Img, Rva);
    if (off == 0xFFFFFFFF || off >= Img->Bytes.size()) return nullptr;
    return Img->Bytes.data() + off;
}

static u32 PeExportRva(const PE_IMAGE* Img, const char* Name)
{
    const u8* b = Img->Bytes.data();
    u32 e = *(u32*)(b + 0x3C);
    const u8* nth = b + e;
    u32 dirRva = *(u32*)(nth + 0x18 + 0x70);
    u32 dirSize = *(u32*)(nth + 0x18 + 0x74);
    if (dirRva == 0 || dirSize == 0) return 0;
    const u8* dir = PeRvaPtr(Img, dirRva);
    if (!dir) return 0;
    u32 nNames = *(u32*)(dir + 24);
    u32 namesRva = *(u32*)(dir + 32);
    u32 ordRva = *(u32*)(dir + 36);
    u32 funcRva = *(u32*)(dir + 28);
    for (u32 i = 0; i < nNames; i++)
    {
        const u8* pn = PeRvaPtr(Img, *(u32*)PeRvaPtr(Img, namesRva + i * 4));
        if (pn && strcmp((const char*)pn, Name) == 0)
        {
            u16 ord = *(u16*)PeRvaPtr(Img, ordRva + i * 2);
            return *(u32*)PeRvaPtr(Img, funcRva + ord * 4);
        }
    }
    return 0;
}

// ntdll stub：0x40 字节内找 mov eax, imm32。
static u32 ExtractSyscall(const PE_IMAGE* Ntdll, const char* Name)
{
    u32 rva = PeExportRva(Ntdll, Name);
    if (rva == 0) return 0;
    const u8* s = PeRvaPtr(Ntdll, rva);
    if (!s) return 0;
    for (u32 i = 0; i + 5 <= 0x40; i++)
        if (s[i] == 0xB8) return *(u32*)(s + i + 1);
    return 0;
}

struct PrecheckEntry
{
    const char* Name;
    u32 Syscall;
    u64 Address;
    bool IsSyscall;
    bool Resolved;
};

static const char* g_Names[] = {
    "NtQueryInformationProcess", "NtQuerySystemInformation",
    "RtlFindExportedRoutineByName", "NtWriteVirtualMemory",
    "NtReadVirtualMemory", "NtDebugActiveProcess", "NtSetContextThread",
};
static const bool g_IsSyscall[] = { true, true, false, true, true, true, true };
#define NAME_COUNT (sizeof(g_Names) / sizeof(g_Names[0]))

static u32 FindServiceTable(const PE_IMAGE* K, u64 Qip, u32 QipSc,
                            u64 Qsi, u32 QsiSc, u32* OutKind)
{
    u64 mz = K->ImageBase;
    u32 endRva = K->SizeOfImage;
    u32 qipRva = (u32)(Qip - mz);
    bool hasQsi = (Qsi != 0 && QsiSc != 0);
    const u8* base = K->Bytes.data();

    // 8B 绝对表
    if (hasQsi)
    {
        for (u32 rva = 0; rva + 16 < endRva; rva += 0x1000)
        {
            const u8* p = PeRvaPtr(K, rva);
            if (!p) continue;
            u32 maxOff = (QipSc * 8 + 8 > QsiSc * 8 + 8) ? QipSc * 8 + 8 : QsiSc * 8 + 8;
            for (u32 off = 0; off + maxOff <= 0x1000; off += 8)
            {
                u64 v1 = *(u64*)(p + off + QipSc * 8);
                u64 v2 = *(u64*)(p + off + QsiSc * 8);
                if (v1 == Qip && v2 == Qsi) { *OutKind = 8; return rva + off; }
            }
        }
    }

    // 4B RVA 表（QIP 命中收集 + 64 条目表特征验证）
    struct Hit { u32 rva; };
    Hit hits[8];
    u32 hitCount = 0;
    for (u32 rva = 0; rva + 4 < endRva; rva += 0x1000)
    {
        const u8* p = PeRvaPtr(K, rva);
        if (!p) continue;
        u32 maxOff = (QipSc * 4 + 4 > QsiSc * 4 + 4) ? QipSc * 4 + 4 : QsiSc * 4 + 4;
        for (u32 off = 0; off + maxOff <= 0x1000; off += 4)
        {
            i64 o1 = (i32)*(u32*)(p + off + QipSc * 4);
            if (hasQsi)
            {
                i64 o2 = (i32)*(u32*)(p + off + QsiSc * 4);
                if ((u64)((i64)mz + o1) == Qip && (u64)((i64)mz + o2) == Qsi)
                { *OutKind = 4; return rva + off; }
            }
            if (o1 == qipRva && hitCount < 8) hits[hitCount++].rva = rva + off;
        }
    }
    for (u32 h = 0; h < hitCount; h++)
    {
        const u8* X = PeRvaPtr(K, hits[h].rva);
        if (!X) continue;
        bool looks = true;
        for (u32 e = 0; e < 64; e++)
        {
            u32 ev = *(u32*)(X + e * 4);
            if (ev < 0x1000 || ev >= K->SizeOfImage) { looks = false; break; }
        }
        if (looks) { *OutKind = 4; return hits[h].rva; }
    }
    return 0;
}

static u64 ReadEntry(const PE_IMAGE* K, u32 TableRva, u32 Sc, bool Is4B)
{
    const u8* p = PeRvaPtr(K, TableRva + Sc * (Is4B ? 4 : 8));
    if (!p) return 0;
    if (Is4B)
    {
        i64 o = (i32)*(u32*)p;
        return (o == 0) ? 0 : (u64)((i64)K->ImageBase + o);
    }
    return *(u64*)p;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::printf("usage: %s <ntoskrnl.exe> <ntdll.dll>\n", argv[0]);
        return 2;
    }
    PE_IMAGE k, n;
    if (!PeLoad(argv[1], &k)) { std::printf("FAIL: cannot load %s\n", argv[1]); return 2; }
    if (!PeLoad(argv[2], &n)) { std::printf("FAIL: cannot load %s\n", argv[2]); return 2; }

    PrecheckEntry e[NAME_COUNT];
    for (size_t i = 0; i < NAME_COUNT; i++)
    {
        e[i].Name = g_Names[i];
        e[i].IsSyscall = g_IsSyscall[i];
        e[i].Syscall = g_IsSyscall[i] ? ExtractSyscall(&n, g_Names[i]) : 0;
        u32 rva = PeExportRva(&k, g_Names[i]);
        if (rva == 0 && strncmp(g_Names[i], "Nt", 2) == 0)
        {
            std::string zw = "Zw" + std::string(g_Names[i] + 2);
            rva = PeExportRva(&k, zw.c_str());
        }
        e[i].Address = rva ? k.ImageBase + rva : 0;
        e[i].Resolved = e[i].Address != 0;
    }

    u32 kind = 0;
    u32 table = FindServiceTable(&k, e[0].Address, e[0].Syscall,
                                 e[1].Address, e[1].Syscall, &kind);

    //
    // 未导出（Win11 24H2+）的系统：用 SSDT 表条目补解析。
    //
    if (table)
    {
        for (size_t i = 0; i < NAME_COUNT; i++)
        {
            if (!e[i].IsSyscall || e[i].Resolved || e[i].Syscall == 0) continue;
            u64 via = ReadEntry(&k, table, e[i].Syscall, kind == 4);
            if (via != 0)
            {
                e[i].Address = via;
                e[i].Resolved = true;
            }
        }
    }

    std::printf("== NpHv P0 TestSyscall ==\n");
    std::printf("ntoskrnl: %s  base=0x%llx size=0x%x\n", argv[1],
                (unsigned long long)k.ImageBase, k.SizeOfImage);
    std::printf("ntdll   : %s\n\n", argv[2]);
    std::printf("%-32s syscall  %-18s %s\n", "name", "address", "status");
    bool allPassed = true;
    for (size_t i = 0; i < NAME_COUNT; i++)
    {
        bool ok = e[i].IsSyscall
                      ? (e[i].Syscall != 0 && e[i].Resolved)
                      : e[i].Resolved;
        if (!ok) allPassed = false;
        std::printf("%-32s %-8s 0x%-16llx %s\n", e[i].Name,
                    e[i].IsSyscall ? std::to_string(e[i].Syscall).c_str() : "-",
                    (unsigned long long)e[i].Address, ok ? "OK" : "MISSING");
    }

    std::printf("\nServiceTable: %s (kind=%uB)\n",
                table ? "FOUND" : "NOT FOUND", kind ? kind : 4);
    bool cross = false;
    if (table)
    {
        for (size_t i = 0; i < NAME_COUNT; i++)
        {
            if (!e[i].IsSyscall || e[i].Syscall == 0) continue;
            u64 via = ReadEntry(&k, table, e[i].Syscall, kind == 4);
            bool same = (via == e[i].Address);
            cross = cross || same;
            std::printf("  %-30s via-table 0x%-16llx %s\n", e[i].Name,
                        (unsigned long long)via, same ? "MATCH" : "diff");
        }
    }

    // RLFE 确认非 syscall（导出且 ntdll 无 stub）
    bool rlfeNotSyscall = (ExtractSyscall(&n, "RtlFindExportedRoutineByName") == 0);
    std::printf("\nRtlFindExportedRoutineByName: non-syscall=%s\n",
                rlfeNotSyscall ? "confirmed" : "UNEXPECTED stub");
    if (!rlfeNotSyscall) allPassed = false;

    bool final = allPassed && table;
    std::printf("\nRESULT: %s\n", final ? "ALL PASSED" : "FAILED");
    return final ? 0 : 1;
}
