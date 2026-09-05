/*!
    @file       TestDisasm.cpp

    @brief      指令长度解码器单元测试（主机环境，MinGW g++ 编译运行）。
                手工指令表 + 若传参 --ground-truth 则读取 objdump 生成
                的真值文件做交叉验证。
 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

#include "NpDisasm.hpp"

using namespace NptHook;

static int g_Failures = 0;

static void
CheckOne(
    _In_ const char* Name,
    _In_ const std::vector<std::uint8_t>& Bytes,
    _In_ std::uint32_t Expected)
{
    std::uint32_t len = GetInstructionLength(Bytes.data(), 15);
    if (len != Expected)
    {
        std::printf("FAIL %-28s bytes=[", Name);
        for (size_t k = 0; k < Bytes.size(); k++)
        {
            std::printf("%02x ", Bytes[k]);
        }
        std::printf("] expected=%u got=%u\n", Expected, len);
        g_Failures++;
    }
}

static void
CheckProlog(
    _In_ const char* Name,
    _In_ const std::vector<std::uint8_t>& Bytes,
    _In_ std::uint32_t MinLen,
    _In_ std::uint32_t Expected)
{
    std::uint32_t len = 0;
    bool ok = GetPrologueLength(Bytes.data(), MinLen, &len);
    bool passed;
    if (Expected == 0)
    {
        passed = !ok;   // 期望解码失败
    }
    else
    {
        passed = ok && len == Expected;
    }
    if (!passed)
    {
        std::printf("FAIL %-28s prolog(min=%u) expected=%u got=%u ok=%d\n",
                    Name, MinLen, Expected, len, ok ? 1 : 0);
        g_Failures++;
    }
}

int
main(int argc, char** argv)
{
    bool groundTruth = (argc > 1 && std::strcmp(argv[1], "--ground-truth") == 0);

    //
    // 手工指令表（字节 + 期望长度）
    //
    struct T
    {
        const char* name;
        std::vector<std::uint8_t> bytes;
        std::uint32_t len;
    };
    std::vector<T> table = {
        // ---- 前缀 ----
        { "lock add [rax], eax",        {0xF0, 0x01, 0x00}, 3 },
        { "rep movsb",                  {0xF3, 0xA4}, 2 },
        { "repne scasb",                {0xF2, 0xAE}, 2 },
        { "fs mov eax, fs:[0x30]",      {0x64, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}, 8 },
        { "gs mov rax, gs:[0x10]",      {0x65, 0x48, 0x8B, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00}, 9 },
        // ---- REX ----
        { "mov rax, rbx",               {0x48, 0x89, 0xD8}, 3 },
        { "mov r8, r9",                 {0x4D, 0x89, 0xC8}, 3 },
        { "mov al, r10b",               {0x41, 0x88, 0xC2}, 3 },
        // ---- 基本算术 ----
        { "add eax, 0x12345678",        {0x05, 0x78, 0x56, 0x34, 0x12}, 5 },
        { "add rax, 0x12345678",        {0x48, 0x05, 0x78, 0x56, 0x34, 0x12}, 6 },
        { "add ax, 0x1234",             {0x66, 0x05, 0x34, 0x12}, 4 },
        { "add al, 0x12",               {0x04, 0x12}, 2 },
        { "sub rsp, 0x28",              {0x48, 0x83, 0xEC, 0x28}, 4 },
        { "sub rsp, 0x12345678",        {0x48, 0x81, 0xEC, 0x78, 0x56, 0x34, 0x12}, 7 },
        { "add [rcx+0x10], rdx",        {0x48, 0x01, 0x51, 0x10}, 4 },
        { "mov [rsp+8], rbx",           {0x48, 0x89, 0x5C, 0x24, 0x08}, 5 },
        { "mov [rsp+0x10], rdi",        {0x48, 0x89, 0x7C, 0x24, 0x10}, 5 },
        { "cmp [rax], rcx",             {0x48, 0x39, 0x08}, 3 },
        { "and eax, 0xFF",              {0x25, 0xFF, 0x00, 0x00, 0x00}, 5 },
        { "or rax, 1",                  {0x48, 0x83, 0xC8, 0x01}, 4 },
        // ---- push/pop ----
        { "push rbx",                   {0x53}, 1 },
        { "push rbp",                   {0x55}, 1 },
        { "pop rbx",                    {0x5B}, 1 },
        { "pop rbp",                    {0x5D}, 1 },
        { "push 0x1234",                {0x68, 0x34, 0x12, 0x00, 0x00}, 5 },
        { "push 0x12",                  {0x6A, 0x12}, 2 },
        { "push r15",                   {0x41, 0x57}, 2 },
        // ---- lea ----
        { "lea rax, [rip+0x10]",        {0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00}, 7 },
        { "lea rcx, [rsp+0x30]",        {0x48, 0x8D, 0x4C, 0x24, 0x30}, 5 },
        { "lea rdx, [rax+rbx*4]",       {0x48, 0x8D, 0x14, 0x98}, 4 },
        { "lea r8, [r9+r10*8+0x100]",   {0x4F, 0x8D, 0x84, 0xD1, 0x00, 0x01, 0x00, 0x00}, 8 },
        { "lea eax, [rbx+0x12345678]",  {0x8D, 0x83, 0x78, 0x56, 0x34, 0x12}, 6 },
        // ---- mov 立即数 ----
        { "mov rax, 0x1122334455667788",{0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}, 10 },
        { "mov eax, 0x12345678",        {0xB8, 0x78, 0x56, 0x34, 0x12}, 5 },
        { "mov ax, 0x1234",             {0x66, 0xB8, 0x34, 0x12}, 4 },
        { "mov al, 0x12",               {0xB0, 0x12}, 2 },
        { "mov r11, 0x12345678",        {0x49, 0xBB, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00}, 10 },
        { "mov dword [rax], 0x1234",    {0xC7, 0x00, 0x34, 0x12, 0x00, 0x00}, 6 },
        { "mov byte [rax], 0x12",       {0xC6, 0x00, 0x12}, 3 },
        // ---- test/cmp ----
        { "test rax, rax",              {0x48, 0x85, 0xC0}, 3 },
        { "test eax, eax",              {0x85, 0xC0}, 2 },
        { "test al, 0x1",               {0xA8, 0x01}, 2 },
        { "test eax, 0x12345678",       {0xA9, 0x78, 0x56, 0x34, 0x12}, 5 },
        { "test byte [rax], 0x1",       {0xF6, 0x00, 0x01}, 3 },
        { "test dword [rax], 0x1234",   {0xF7, 0x00, 0x34, 0x12, 0x00, 0x00}, 6 },
        { "not rax",                    {0x48, 0xF7, 0xD0}, 3 },
        { "neg rax",                    {0x48, 0xF7, 0xD8}, 3 },
        { "mul rbx",                    {0x48, 0xF7, 0xE3}, 3 },
        { "div rcx",                    {0x48, 0xF7, 0xF1}, 3 },
        // ---- 跳转 ----
        { "jmp short +0x10",            {0xEB, 0x10}, 2 },
        { "jmp far +0x12345678",        {0xE9, 0x78, 0x56, 0x34, 0x12}, 5 },
        { "call +0x12345678",           {0xE8, 0x78, 0x56, 0x34, 0x12}, 5 },
        { "jz +0x10",                   {0x74, 0x10}, 2 },
        { "jnz far +0x12345678",        {0x0F, 0x85, 0x78, 0x56, 0x34, 0x12}, 6 },
        { "loop +0x10",                 {0xE2, 0x10}, 2 },
        { "jrcxz +0x10",                {0xE3, 0x10}, 2 },
        // ---- 函数结尾 ----
        { "ret",                        {0xC3}, 1 },
        { "ret 0x10",                   {0xC2, 0x10, 0x00}, 3 },
        { "leave",                      {0xC9}, 1 },
        { "int3",                       {0xCC}, 1 },
        { "int 0x2e",                   {0xCD, 0x2E}, 2 },
        { "nop",                        {0x90}, 1 },
        { "multi-byte nop",             {0x0F, 0x1F, 0x40, 0x00}, 4 },
        // ---- 扩展指令 ----
        { "syscall",                    {0x0F, 0x05}, 2 },
        { "sysret",                     {0x0F, 0x07}, 2 },
        { "cpuid",                      {0x0F, 0xA2}, 2 },
        { "rdtsc",                      {0x0F, 0x31}, 2 },
        { "rdmsr",                      {0x0F, 0x32}, 2 },
        { "wrmsr",                      {0x0F, 0x30}, 2 },
        { "ud2",                        {0x0F, 0x0B}, 2 },
        { "bswap rax",                  {0x48, 0x0F, 0xC8}, 3 },
        { "movzx eax, byte [rcx]",      {0x0F, 0xB6, 0x01}, 3 },
        { "movzx rax, word [rcx+4]",    {0x48, 0x0F, 0xB7, 0x41, 0x04}, 5 },
        { "movsx rax, dword [rbx]",     {0x48, 0x63, 0x03}, 3 },
        { "movsx eax, byte [rax]",      {0x0F, 0xBE, 0x00}, 3 },
        { "imul rax, rbx",              {0x48, 0x0F, 0xAF, 0xC3}, 4 },
        { "imul rax, rbx, 0x10",        {0x48, 0x6B, 0xC3, 0x10}, 4 },
        { "imul rax, rbx, 0x12345678",  {0x48, 0x69, 0xC3, 0x78, 0x56, 0x34, 0x12}, 7 },
        { "shl rax, 1",                 {0x48, 0xD1, 0xE0}, 3 },
        { "shl rax, cl",                {0x48, 0xD3, 0xE0}, 3 },
        { "shl rax, 5",                 {0x48, 0xC1, 0xE0, 0x05}, 4 },
        { "shld rax, rbx, 3",           {0x48, 0x0F, 0xA4, 0xD8, 0x03}, 5 },
        { "shrd rax, rbx, 3",           {0x48, 0x0F, 0xAC, 0xD8, 0x03}, 5 },
        { "bt [rax], 3",                {0x0F, 0xBA, 0x20, 0x03}, 4 },
        { "bts [rax], 3",               {0x48, 0x0F, 0xAB, 0x20}, 4 },
        { "setz al",                    {0x0F, 0x94, 0xC0}, 3 },
        { "cmovz rax, rbx",             {0x48, 0x0F, 0x44, 0xC3}, 4 },
        { "cmpxchg [rax], rbx",         {0x48, 0x0F, 0xB1, 0x18}, 4 },
        { "xadd [rax], rbx",            {0x48, 0x0F, 0xC1, 0x18}, 4 },
        // ---- SSE ----
        { "movaps xmm0, [rax]",         {0x0F, 0x28, 0x00}, 3 },
        { "movaps [rax], xmm0",         {0x0F, 0x29, 0x00}, 3 },
        { "pxor xmm0, xmm0",            {0x66, 0x0F, 0xEF, 0xC0}, 4 },
        { "movdqu xmm1, [rcx]",         {0xF3, 0x0F, 0x6F, 0x09}, 4 },
        { "pshufd xmm0, xmm0, 0x1b",    {0x66, 0x0F, 0x70, 0xC0, 0x1B}, 5 },
        { "shufps xmm0, xmm1, 0x10",    {0x0F, 0xC6, 0xC1, 0x10}, 4 },
        { "cmpps xmm0, xmm1, 0",        {0x0F, 0xC2, 0xC1, 0x00}, 4 },
        { "movd eax, xmm0",             {0x66, 0x0F, 0x7E, 0xC0}, 4 },
        { "movq xmm0, rax",             {0x66, 0x48, 0x0F, 0x6E, 0xC0}, 5 },
        // ---- 字符串/moffs ----
        { "mov rax, [0x12345678]",      {0x48, 0xA1, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00}, 10 },
        { "mov eax, [0x12345678]",      {0xA1, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00}, 9 },
        { "mov eax, [0x12345678]",      {0x67, 0xA1, 0x78, 0x56, 0x34, 0x12}, 6 },
        { "movsb",                      {0xA4}, 1 },
        { "stosq",                      {0x48, 0xAB}, 2 },
        { "lodsb",                      {0xAC}, 1 },
        // ---- 其他 ----
        { "mov cr0, rax",               {0x0F, 0x22, 0xC0}, 3 },
        { "mov rax, cr0",               {0x0F, 0x20, 0xC0}, 3 },
        { "in eax, dx",                 {0xED}, 1 },
        { "out dx, al",                 {0xEE}, 1 },
        { "in al, 0x60",                {0xE4, 0x60}, 2 },
        { "hlt",                        {0xF4}, 1 },
        { "cli",                        {0xFA}, 1 },
        { "sti",                        {0xFB}, 1 },
        { "cld",                        {0xFC}, 1 },
        { "std",                        {0xFD}, 1 },
        { "enter 0x100, 0",             {0xC8, 0x00, 0x01, 0x00}, 4 },
        { "pushfq",                     {0x9C}, 1 },
        { "popfq",                      {0x9D}, 1 },
        { "cdqe",                       {0x48, 0x98}, 2 },
        { "xlat",                       {0xD7}, 1 },
        { "movsxd rax, r8d",            {0x4C, 0x63, 0xC0}, 3 },
        // ---- x87 ----
        { "fldz",                       {0xD9, 0xEE}, 2 },
        { "fld [rax]",                  {0xD9, 0x00}, 2 },
        { "fld qword [rax+0x8]",        {0xDD, 0x40, 0x08}, 3 },
        { "fstp st(0)",                 {0xDD, 0xD8}, 2 },
        // ---- 非法编码应失败 ----
        { "bound (invalid)",            {0x62, 0x18}, 0 },
        { "vex prefix (unsupported)",   {0xC5, 0xF8, 0x58, 0xC0}, 0 },
        { "push cs (invalid64)",        {0x0E}, 0 },
    };

    for (const auto& t : table)
    {
        CheckOne(t.name, t.bytes, t.len);
    }

    //
    // 序言计算测试：连续解码直到 >= MinLength
    // （缓冲区补 NOP 填充，模拟真实函数后续字节）
    //
    CheckProlog("mov [rsp+8],rbx;mov [rsp+10h],rdi",
                {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x7C, 0x24, 0x10}, 5, 5);
    CheckProlog("sub rsp,0x28;mov rax,rcx", {0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xC8}, 5, 7);
    CheckProlog("push rbp;mov rbp,rsp;sub rsp,0x20", {0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x20}, 5, 8);
    // 单字节指令 + NOP 填充：仍能解码到 >=5 字节（驱动侧会拒绝这类无意义目标）
    CheckProlog("int3+nops", {0xCC, 0x90, 0x90, 0x90, 0x90}, 5, 5);
    CheckProlog("ret+nops", {0xC3, 0x90, 0x90, 0x90, 0x90}, 5, 5);
    // 无法解码的字节流 → 失败
    CheckProlog("vex prefix", {0xC5, 0xF8, 0x58, 0xC0, 0x90, 0x90}, 5, 0);

    //
    // 可选：与 objdump 真值交叉验证
    //
    if (groundTruth)
    {
        // 格式：每行 "hexbytes<tab>expectedLen"
        std::vector<std::pair<std::string, std::uint32_t>> gt;
        char line[1024];
        while (std::fgets(line, sizeof(line), stdin) != nullptr)
        {
            char* tab = std::strchr(line, '\t');
            if (tab == nullptr)
            {
                continue;
            }
            *tab = '\0';
            gt.emplace_back(line, static_cast<std::uint32_t>(std::strtoul(tab + 1, nullptr, 10)));
        }
        for (const auto& [hexstr, expected] : gt)
        {
            std::vector<std::uint8_t> bytes;
            for (size_t k = 0; k + 1 < hexstr.length(); k += 3)
            {
                bytes.push_back(static_cast<std::uint8_t>(
                    std::strtoul(hexstr.substr(k, 2).c_str(), nullptr, 16)));
            }
            CheckOne(("gt:" + hexstr).c_str(), bytes, expected);
        }
        std::printf("Ground-truth entries: %zu\n", gt.size());
    }

    if (g_Failures == 0)
    {
        std::printf("ALL TESTS PASSED (%zu manual cases)\n", table.size());
        return 0;
    }
    std::printf("FAILURES: %d\n", g_Failures);
    return 1;
}
