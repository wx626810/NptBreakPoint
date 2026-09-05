/*!
    @file       NpHvCtl.cpp

    @brief      R3 管理工具：通过 IOCTL 协议控制 NpHv Hypervisor。

    @details    完整命令参考见 docs/NpHvCtl-命令参考.md。摘要：

        NpHvCtl status                    # 查询状态（版本/HV/CPU/Hook 数）
        NpHvCtl hook <name|addr> <action> [ret]   # 安装 NPT Hook
                action: log(记录放行) / ret(拦截返回指定值) / pass(放行) / code(注入机器码)
        NpHvCtl unhook <hookid>           # 卸载 Hook
        NpHvCtl unhookall                 # 卸载全部 Hook
        NpHvCtl unload                    # 卸载 Hypervisor
        NpHvCtl demo                      # 完整演示序列（默认命令）

        # ---- NPT 无痕断点 / 监视 ----
        NpHvCtl bp <name|addr> [halt|oneshot]     # 装断点（默认自动单步）
        NpHvCtl bpdel <id>                # 卸载断点
        NpHvCtl bplist                    # 列出断点与命中统计
        NpHvCtl bpcont <id|all>           # 继续暂停的断点
        NpHvCtl mon <name|addr> <r|w|rw>  # NPT 数据访问监视
        NpHvCtl mondel <id>               # 卸载监视

        # ---- DR 硬件断点虚拟化 ----
        NpHvCtl drprobe on|off            # 开启/关闭 DR 拦截（探测+伪造）
        NpHvCtl drstate                   # 查询假 DR 与调试器设的硬件断点

        # ---- X64DBG 调试链路隐藏 ----
        NpHvCtl dbg hide on|off           # 开启/关闭调试隐藏（Hook 3 个 Nt*）
        NpHvCtl dbg protect <pid>         # 注册调试目标（白名单=隐藏目标）
        NpHvCtl dbg unprotect <pid>       # 注销
        NpHvCtl dbg mode white|black      # 白名单=仅注册 PID 隐藏；黑名单=除注册 PID 外全部隐藏

        # ---- 无痕内存读写 ----
        NpHvCtl mem <pid> <addr> <len>    # 物理直读目标进程内存（hex 输出）

    编译（MinGW，输出到 output\）：
        build_ctl.bat
        # 或：g++ -O2 -mwindows -I../NptHook/include NpHvCtl.cpp -o ../output/NpHvCtl.exe
        #     -mwindows = GUI 子系统：GUI 启动无控制台黑框；CLI 带参时运行时附着控制台
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "DrvMgr.h"
#include "SecCheck.h"
#include "Hypercall.h"
#include "CiPatch.h"
#include <winioctl.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include "../NptHook/include/NpIoctl.h"
// 字符串混淆表（脚本生成：npobf_gen.py，勿手改）：密文存 .data
// （非 const，防优化器折叠），运行时 NpDec 解密到 g_decBuf。
// 字符串字面量本身必落盘，故此处只存密文字节数组初始化器。
static unsigned char g_obs[35][61] = {
    {0x06,0x06,0x74,0x06,0x14,0x2A,0x12,0x2C},   // len=8
    {0x01,0x7B,0x07,0x7A,0x0B,0x2F,0x3F,0x28,0x23,0x09,0x2E,0x3B,0x2E,0x2F,0x29,0x7A,0x3C,0x3B,0x33,0x36,0x3F,0x3E,0x7A,0x72,0x3F,0x28,0x28,0x67,0x7F,0x36,0x2F,0x73,0x50},   // len=33
    {0x14,0x2A,0x12,0x2C,0x7A,0x29,0x2E,0x3B,0x2E,0x2F,0x29,0x60,0x50},   // len=13
    {0x7A,0x7A,0x2A,0x28,0x35,0x2E,0x35,0x39,0x35,0x36,0x7A,0x2C,0x3F,0x28,0x29,0x33,0x35,0x34,0x7A,0x7A,0x7A,0x60,0x7A,0x7F,0x2F,0x50},   // len=26
    {0x7A,0x7A,0x32,0x23,0x2A,0x3F,0x28,0x2C,0x33,0x29,0x35,0x28,0x7A,0x28,0x2F,0x34,0x34,0x33,0x34,0x3D,0x7A,0x60,0x7A,0x7F,0x29,0x50},   // len=26
    {0x7A,0x7A,0x2A,0x28,0x35,0x39,0x3F,0x29,0x29,0x35,0x28,0x29,0x7A,0x7A,0x7A,0x7A,0x7A,0x7A,0x7A,0x7A,0x7A,0x60,0x7A,0x7F,0x2F,0x50},   // len=26
    {0x7A,0x7A,0x3B,0x39,0x2E,0x33,0x2C,0x3F,0x7A,0x32,0x35,0x35,0x31,0x29,0x7A,0x7A,0x7A,0x7A,0x7A,0x7A,0x7A,0x60,0x7A,0x7F,0x2F,0x50},   // len=26
    {0x7A,0x7A,0x3E,0x28,0x33,0x2C,0x3F,0x28,0x7A,0x29,0x3F,0x36,0x3C,0x77,0x32,0x33,0x3E,0x3F,0x7A,0x7A,0x7A,0x60,0x7A,0x7F,0x29,0x50},   // len=26
    {0x2F,0x29,0x3B,0x3D,0x3F,0x60,0x7A,0x32,0x35,0x35,0x31,0x7A,0x66,0x34,0x3B,0x37,0x3F,0x26,0x6A,0x22,0x3B,0x3E,0x3E,0x28,0x64,0x7A,0x66,0x36,0x35,0x3D,0x26,0x28,0x3F,0x2E,0x26,0x2A,0x3B,0x29,0x29,0x64,0x7A,0x01,0x28,0x3F,0x2E,0x2C,0x3B,0x36,0x07,0x50},   // len=50
    {0x36,0x35,0x3D},   // len=3
    {0x01,0x7B,0x07,0x7A,0x2F,0x34,0x31,0x34,0x35,0x2D,0x34,0x7A,0x3B,0x39,0x2E,0x33,0x35,0x34,0x7A,0x7D,0x7F,0x29,0x7D,0x7A,0x72,0x36,0x35,0x3D,0x26,0x28,0x3F,0x2E,0x26,0x2A,0x3B,0x29,0x29,0x26,0x39,0x35,0x3E,0x3F,0x73,0x50},   // len=44
    {0x01,0x7B,0x07,0x7A,0x13,0x34,0x29,0x2E,0x3B,0x36,0x36,0x12,0x35,0x35,0x31,0x7A,0x3C,0x3B,0x33,0x36,0x3F,0x3E,0x7A,0x72,0x3F,0x28,0x28,0x67,0x7F,0x36,0x2F,0x73,0x50},   // len=33
    {0x01,0x7B,0x07,0x7A,0x13,0x34,0x29,0x2E,0x3B,0x36,0x36,0x12,0x35,0x35,0x31,0x60,0x7A,0x7F,0x29,0x7A,0x72,0x6A,0x22,0x7F,0x6A,0x62,0x22,0x73,0x50},   // len=29
    {0x01,0x71,0x07,0x7A,0x12,0x35,0x35,0x31,0x7A,0x33,0x34,0x29,0x2E,0x3B,0x36,0x36,0x3F,0x3E,0x60,0x7A,0x33,0x3E,0x67,0x7F,0x2F,0x50},   // len=26
    {0x01,0x7B,0x07,0x7A,0x0F,0x34,0x33,0x34,0x29,0x2E,0x3B,0x36,0x36,0x12,0x35,0x35,0x31,0x7A,0x3C,0x3B,0x33,0x36,0x3F,0x3E,0x7A,0x72,0x3F,0x28,0x28,0x67,0x7F,0x36,0x2F,0x73,0x50},   // len=35
    {0x01,0x71,0x07,0x7A,0x12,0x35,0x35,0x31,0x7A,0x7F,0x36,0x2F,0x7A,0x28,0x3F,0x37,0x35,0x2C,0x3F,0x3E,0x50},   // len=21
    {0x01,0x7B,0x07,0x7A,0x0F,0x34,0x33,0x34,0x29,0x2E,0x3B,0x36,0x36,0x1B,0x36,0x36,0x7A,0x3C,0x3B,0x33,0x36,0x3F,0x3E,0x7A,0x72,0x3F,0x28,0x28,0x67,0x7F,0x36,0x2F,0x73,0x50},   // len=34
    {0x01,0x71,0x07,0x7A,0x1B,0x36,0x36,0x7A,0x32,0x35,0x35,0x31,0x29,0x7A,0x28,0x3F,0x37,0x35,0x2C,0x3F,0x3E,0x50},   // len=22
    {0x01,0x7B,0x07,0x7A,0x1E,0x3F,0x2C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x33,0x20,0x3F,0x7A,0x3C,0x3B,0x33,0x36,0x3F,0x3E,0x7A,0x72,0x3F,0x28,0x28,0x67,0x7F,0x36,0x2F,0x73,0x50},   // len=34
    {0x01,0x71,0x07,0x7A,0x12,0x23,0x2A,0x3F,0x28,0x2C,0x33,0x29,0x35,0x28,0x7A,0x3E,0x3F,0x2C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x33,0x20,0x3F,0x3E,0x7A,0x72,0x08,0x69,0x7A,0x28,0x3F,0x2B,0x2F,0x3F,0x29,0x2E,0x73,0x50},   // len=42
    {0x67,0x67,0x67,0x7A,0x14,0x2A,0x12,0x2C,0x19,0x2E,0x36,0x7A,0x3E,0x3F,0x37,0x35,0x7A,0x67,0x67,0x67,0x50},   // len=21
    {0x50,0x01,0x29,0x2E,0x3F,0x2A,0x07,0x7A,0x33,0x34,0x29,0x2E,0x3B,0x36,0x36,0x7A,0x16,0x35,0x3D,0x15,0x34,0x36,0x23,0x7A,0x32,0x35,0x35,0x31,0x7A,0x35,0x34,0x7A,0x14,0x2E,0x0B,0x2F,0x3F,0x28,0x23,0x09,0x23,0x29,0x2E,0x3F,0x37,0x13,0x34,0x3C,0x35,0x28,0x37,0x3B,0x2E,0x33,0x35,0x34,0x50},   // len=57
    {0x14,0x2E,0x0B,0x2F,0x3F,0x28,0x23,0x09,0x23,0x29,0x2E,0x3F,0x37,0x13,0x34,0x3C,0x35,0x28,0x37,0x3B,0x2E,0x33,0x35,0x34},   // len=24
    {0x01,0x71,0x07,0x7A,0x12,0x35,0x35,0x31,0x7A,0x33,0x3E,0x67,0x7F,0x2F,0x7A,0x33,0x34,0x29,0x2E,0x3B,0x36,0x36,0x3F,0x3E,0x50},   // len=25
    {0x50,0x01,0x29,0x2E,0x3F,0x2A,0x07,0x7A,0x2E,0x28,0x33,0x3D,0x3D,0x3F,0x28,0x7A,0x14,0x2E,0x0B,0x2F,0x3F,0x28,0x23,0x09,0x23,0x29,0x2E,0x3F,0x37,0x13,0x34,0x3C,0x35,0x28,0x37,0x3B,0x2E,0x33,0x35,0x34,0x7A,0x22,0x6F,0x7A,0x72,0x39,0x32,0x3F,0x39,0x31,0x7A,0x14,0x2A,0x12,0x2C,0x74,0x36,0x35,0x3D,0x73,0x50},   // len=61
    {0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36},   // len=9
    {0x7A,0x7A,0x39,0x3B,0x36,0x36,0x7A,0x79,0x7F,0x3E,0x7A,0x77,0x64,0x7A,0x29,0x2E,0x3B,0x2E,0x2F,0x29,0x67,0x6A,0x22,0x7F,0x6A,0x62,0x22,0x50},   // len=28
    {0x7A,0x7A,0x01,0x7B,0x07,0x7A,0x39,0x3B,0x34,0x34,0x35,0x2E,0x7A,0x28,0x3F,0x29,0x35,0x36,0x2C,0x3F,0x7A,0x14,0x2E,0x0B,0x2F,0x3F,0x28,0x23,0x09,0x23,0x29,0x2E,0x3F,0x37,0x13,0x34,0x3C,0x35,0x28,0x37,0x3B,0x2E,0x33,0x35,0x34,0x50},   // len=46
    {0x50,0x01,0x29,0x2E,0x3F,0x2A,0x07,0x7A,0x29,0x2E,0x3B,0x2E,0x2F,0x29,0x7A,0x3B,0x3C,0x2E,0x3F,0x28,0x7A,0x2E,0x28,0x33,0x3D,0x3D,0x3F,0x28,0x29,0x50},   // len=30
    {0x50,0x01,0x29,0x2E,0x3F,0x2A,0x07,0x7A,0x2F,0x34,0x33,0x34,0x29,0x2E,0x3B,0x36,0x36,0x7A,0x32,0x35,0x35,0x31,0x50},   // len=23
    {0x50,0x01,0x71,0x07,0x7A,0x3E,0x3F,0x37,0x35,0x7A,0x3E,0x35,0x34,0x3F,0x74,0x7A,0x7D,0x14,0x2A,0x12,0x2C,0x19,0x2E,0x36,0x7A,0x2F,0x34,0x36,0x35,0x3B,0x3E,0x7D,0x7A,0x2E,0x35,0x7A,0x3E,0x3F,0x2C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x33,0x20,0x3F,0x74,0x50},   // len=50
    {0x14,0x2A,0x12,0x2C,0x19,0x2E,0x36,0x7A,0x77,0x7A,0x08,0x69,0x7A,0x37,0x3B,0x34,0x3B,0x3D,0x3F,0x37,0x3F,0x34,0x2E,0x7A,0x2E,0x35,0x35,0x36,0x7A,0x72,0x2A,0x28,0x35,0x2E,0x35,0x39,0x35,0x36,0x7A,0x2C,0x7F,0x2F,0x73,0x50},   // len=44
    {0x01,0x7B,0x07,0x7A,0x39,0x3B,0x34,0x34,0x35,0x2E,0x7A,0x35,0x2A,0x3F,0x34,0x7A,0x06,0x06,0x74,0x06,0x14,0x2A,0x12,0x2C,0x7A,0x72,0x3F,0x28,0x28,0x67,0x7F,0x36,0x2F,0x73,0x50},   // len=35
    {0x7A,0x7A,0x7A,0x7A,0x3E,0x28,0x33,0x2C,0x3F,0x28,0x7A,0x34,0x35,0x2E,0x7A,0x28,0x2F,0x34,0x34,0x33,0x34,0x3D,0x65,0x7A,0x28,0x2F,0x34,0x60,0x7A,0x29,0x39,0x7A,0x29,0x2E,0x3B,0x28,0x2E,0x7A,0x14,0x2A,0x12,0x2C,0x50},   // len=43
    {0x2F,0x34,0x31,0x34,0x35,0x2D,0x34,0x7A,0x39,0x35,0x37,0x37,0x3B,0x34,0x3E,0x60,0x7A,0x7F,0x29,0x50},   // len=20
};
static const int g_obs_len[] = {8, 33, 13, 26, 26, 26, 26, 26, 50, 3, 44, 33, 29, 26, 35, 21, 34, 22, 34, 42, 21, 57, 24, 25, 61, 9, 28, 46, 30, 23, 50, 44, 35, 43, 20};
static char g_decBuf[256];
__attribute__((noinline))
static const char* NpDec(int id)
{
    for (int i = 0; i < g_obs_len[id]; i++)
        g_decBuf[i] = (char)(g_obs[id][i] ^ 0x5A);
    g_decBuf[g_obs_len[id]] = 0;
    return g_decBuf;
}




// 运行时动态调用 ntdll!NtQuerySystemInformation 以触发演示 Hook
typedef LONG NTSTATUS;
#ifndef NTAPI
#define NTAPI __stdcall
#endif
typedef NTSTATUS(NTAPI* PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);

//

static HANDLE g_hDev = INVALID_HANDLE_VALUE;

// 启动追踪：写到 %TEMP%\NpHvCtl_trace.log，用于定位“进程未出现/
// 无窗口”时卡在哪一步（驱动环境诊断用，不影响功能）。
// R3 trace 开关：0 = CtlTrace 变空操作（不写 %TEMP%\NpHvCtl_trace.log）。
// 注意：部分调用点在调用前先 snprintf 组装字符串，置 0 后格式化仍会执行，
// 但不再产生任何文件输出。发布版置 0。
#ifndef NPHVCTL_TRACE_ENABLE
#define NPHVCTL_TRACE_ENABLE 1
#endif
#if NPHVCTL_TRACE_ENABLE
static void CtlTrace(const char* msg)
{
    char path[MAX_PATH];
    if (GetTempPathA(sizeof(path), path) == 0) return;
    size_t plen = strlen(path);
    if (plen == 0 || plen + 32 >= sizeof(path)) return;
    snprintf(path + plen, sizeof(path) - plen, "NpHvCtl_trace.log");

    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char line[512];
    int n = snprintf(line, sizeof(line), "%lu %s\r\n",
                     (unsigned long)GetTickCount(), msg);
    if (n > 0)
    {
        DWORD w = 0;
        WriteFile(h, line, (DWORD)n, &w, nullptr);
    }
    CloseHandle(h);
}
#else
#define CtlTrace(msg) ((void)0)
#endif
static BOOL OpenDevice(void)
{
    CtlTrace("OpenDevice enter");
    // Try hypercall to get random device first (stealth)
    wchar_t devName[64]={0};
    bool hcOk = HcGetDeviceName(devName, 64);
    {
        char tmp[256]; 
        char ansiDbg[128]={0};
        WideCharToMultiByte(CP_ACP,0,devName,-1,ansiDbg,128,NULL,NULL);
        snprintf(tmp,256,"OpenDevice hcOk=%d devNameLen=%d devName=%s", hcOk?1:0, (int)wcslen(devName), ansiDbg);
        CtlTrace(tmp);
        if(hcOk && devName[0] && wcslen(devName) > 5){
            // Find last backslash correctly
            wchar_t* base = wcsrchr(devName, L'\\');
            if(base) base++; else base=devName;
            // base should be NpHv_*
            char baseAnsi[64]={0};
            WideCharToMultiByte(CP_ACP,0,base,-1,baseAnsi,64,NULL,NULL);
            char logb[160]; snprintf(logb,160,"OpenDevice base=%s", baseAnsi);
            CtlTrace(logb);
            wchar_t dosPath[64];
            swprintf(dosPath, 64, L"\\\\.\\%s", base);
            char ansi[128]; WideCharToMultiByte(CP_ACP,0,dosPath,-1,ansi,128,NULL,NULL);
            char log2[160]; snprintf(log2,160,"OpenDevice trying hypercall path %s", ansi);
            CtlTrace(log2);
            g_hDev = CreateFileA(ansi,
                             GENERIC_READ | GENERIC_WRITE,
                             0,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             nullptr);
            if(g_hDev != INVALID_HANDLE_VALUE){ CtlTrace("OpenDevice hypercall ok"); return TRUE; }
            char log3[64]; snprintf(log3,64,"OpenDevice hypercall CreateFile err=%lu", GetLastError());
            CtlTrace(log3);
        } else {
            CtlTrace("OpenDevice hypercall miss");
        }
    }
    // Fallback: enumerate DosDevices for NpHv_* (handle INSUFFICIENT_BUFFER)
    {
        DWORD bufChars = 32768;
        wchar_t* dosBuf = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, bufChars*sizeof(wchar_t));
        if(dosBuf){
            DWORD ret = QueryDosDeviceW(NULL, dosBuf, bufChars);
            char log4[64]; snprintf(log4,64,"OpenDevice enum ret=%lu err=%lu", ret, GetLastError());
            CtlTrace(log4);
            if(ret && ret < bufChars){
                for(wchar_t* p = dosBuf; *p; ){
                    size_t len = wcslen(p);
                    if(len==0) break;
                    char pAnsi[64]={0};
                    WideCharToMultiByte(CP_ACP,0,p,-1,pAnsi,64,NULL,NULL);
                    char logp[128]; snprintf(logp,128,"OpenDevice enum p=%s len=%zu", pAnsi, len);
                    CtlTrace(logp);
                    if(len>=5 && wcsncmp(p, L"NpHv_", 5)==0){
                        wchar_t dosPath[64];
                        swprintf(dosPath, 64, L"\\\\.\\%s", p);
                        char ansi2[128]; WideCharToMultiByte(CP_ACP,0,dosPath,-1,ansi2,128,NULL,NULL);
                        char log5[160]; snprintf(log5,160,"OpenDevice trying enum %s", ansi2);
                        CtlTrace(log5);
                        g_hDev = CreateFileA(ansi2, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if(g_hDev != INVALID_HANDLE_VALUE){ CtlTrace("OpenDevice enum ok"); HeapFree(GetProcessHeap(),0,dosBuf); return TRUE; }
                        char log6[64]; snprintf(log6,64,"OpenDevice enum CreateFile err=%lu", GetLastError());
                        CtlTrace(log6);
                    }
                    p += len+1;
                }
                CtlTrace("OpenDevice enum no NpHv_ found");
            } else {
                char log7[64]; snprintf(log7,64,"OpenDevice enum QueryDosDevice failed ret=%lu err=%lu", ret, GetLastError());
                CtlTrace(log7);
            }
            HeapFree(GetProcessHeap(),0,dosBuf);
        } else {
            CtlTrace("OpenDevice enum HeapAlloc failed");
        }
    }
    g_hDev = CreateFileA(NpDec(0),
                         GENERIC_READ | GENERIC_WRITE,
                         0,
                         nullptr,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         nullptr);
    CtlTrace(g_hDev != INVALID_HANDLE_VALUE ? "OpenDevice ok" : "OpenDevice failed");
    return (g_hDev != INVALID_HANDLE_VALUE);
}

static const char* NtStatusName(ULONG status)
{
    switch (status)
    {
    case 0:                    return "STATUS_SUCCESS";
    case 0xC000000D:           return "STATUS_INVALID_PARAMETER";
    case 0xC0000004:           return "STATUS_NOT_FOUND";
    case 0xC0000023:           return "STATUS_BUFFER_TOO_SMALL";
    case 0xC000005E:           return "STATUS_INVALID_ADDRESS";
    case 0xC00001A0:           return "STATUS_REVISION_MISMATCH";
    case 0xC000009A:           return "STATUS_INSUFFICIENT_RESOURCES";
    case 0xC00000BB:           return "STATUS_NOT_SUPPORTED";
    default:                   return "STATUS_?";
    }
}

static BOOL Ioctl(ULONG code, PVOID buf, ULONG inLen, ULONG outLen, PULONG returned)
{
    if(g_hDev==INVALID_HANDLE_VALUE) OpenDevice();
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(g_hDev, code, buf, inLen, buf, outLen,
                              &bytesReturned, nullptr);
    if (returned)
    {
        *returned = bytesReturned;
    }
    return ok;
}

static int CmdStatus(void)
{
    NPHV_STATUS_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG returned = 0;
    // Dual-stack: try hypercall first (no device needed)
    bool hcOk = false;
    {
        NPHV_STATUS_RESPONSE hc{};
        if(HcQueryStatus(&hc, sizeof(hc))) { resp=hc; hcOk=true; }
    }
    if (!hcOk && !Ioctl(IOCTL_NPHV_QUERY_STATUS, &resp, 0, sizeof(resp), &returned))
    {
        printf(NpDec(1), GetLastError());
        return 1;
    }
    printf(NpDec(2));
    printf(NpDec(3), resp.Version);
    printf(NpDec(4), resp.HypervisorRunning ? "yes" : "no");
    printf(NpDec(5), resp.ProcessorCount);
    printf(NpDec(6), resp.ActiveHookCount);
    printf(NpDec(7),
           (resp.Flags & NPHV_FLAG_SELF_HIDE) ? "enabled" : "disabled");
    return 0;
}

static int CmdHook(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf(NpDec(8));
        return 1;
    }
    NPHV_INSTALL_HOOK_REQUEST req;
    NPHV_INSTALL_HOOK_RESPONSE resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    req.Version = NPHV_PROTOCOL_VERSION;
    if (strncmp(argv[1], "0x", 2) == 0 || strncmp(argv[1], "0X", 2) == 0)
    {
        req.TargetAddress = strtoull(argv[1], nullptr, 0);
    }
    else
    {
        strncpy_s(req.TargetName, sizeof(req.TargetName), argv[1], _TRUNCATE);
    }

    if (strcmp(argv[2], NpDec(9)) == 0)
    {
        req.Action = NpHookActionLogOnly;
    }
    else if (strcmp(argv[2], "ret") == 0)
    {
        req.Action = NpHookActionReturnValue;
        if (argc >= 4)
        {
            req.ReturnValue = strtoull(argv[3], nullptr, 0);
        }
    }
    else if (strcmp(argv[2], "pass") == 0)
    {
        req.Action = NpHookActionPassThrough;
    }
    else if (strcmp(argv[2], "code") == 0)
    {
        //
        // 演示"R3 传代码"：位置无关 x64 机器码，回调约定见 NpIoctl.h。
        //   mov qword ptr [rcx+0x10], 0x12345678   ; Ctx->Rax = 0x12345678
        //   mov al, 1                               ; return TRUE（拦截）
        //   ret
        //
        static const UCHAR demoCode[] =
        {
            0x48, 0xC7, 0x41, 0x10, 0x78, 0x56, 0x34, 0x12,  // mov [rcx+0x10], 12345678h
            0xB0, 0x01,                                       // mov al, 1
            0xC3                                              // ret
        };
        req.Action = NpHookActionCustomCode;
        req.CodeSize = (uint32_t)sizeof(demoCode);
        memcpy(req.CodeBytes, demoCode, sizeof(demoCode));
    }
    else
    {
        printf(NpDec(10), argv[2]);
        return 1;
    }

    // BUFFERED 模式：请求在前、响应在后。
    // 注意：inLen/outLen 必须都传整个复合缓冲大小（request+response），
    // 否则 SystemBuffer 只按 max(in,out) 分配，内核写响应会越界！
    UCHAR buf[sizeof(NPHV_INSTALL_HOOK_REQUEST) + sizeof(NPHV_INSTALL_HOOK_RESPONSE)];
    memcpy(buf, &req, sizeof(req));
    ULONG returned = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_HOOK, buf,
               sizeof(buf), sizeof(buf), &returned))
    {
        printf(NpDec(11), GetLastError());
        return 1;
    }
    memcpy(&resp, buf + sizeof(NPHV_INSTALL_HOOK_REQUEST), sizeof(resp));

    if (resp.Status != 0)
    {
        printf(NpDec(12), NtStatusName(resp.Status), resp.Status);
        return 1;
    }
    printf(NpDec(13), resp.HookId);
    return 0;
}

static int CmdUnhook(ULONG hookId)
{
    NPHV_UNINSTALL_HOOK_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.HookId = hookId;
    if (!Ioctl(IOCTL_NPHV_UNINSTALL_HOOK, &req, sizeof(req), 0, nullptr))
    {
        printf(NpDec(14), GetLastError());
        return 1;
    }
    printf(NpDec(15), hookId);
    return 0;
}

static int CmdUnhookAll(void)
{
    if (!Ioctl(IOCTL_NPHV_UNINSTALL_ALL, nullptr, 0, 0, nullptr))
    {
        printf(NpDec(16), GetLastError());
        return 1;
    }
    printf(NpDec(17));
    return 0;
}

static int CmdUnload(void)
{
    if (!Ioctl(IOCTL_NPHV_DEVIRTUALIZE, nullptr, 0, 0, nullptr))
    {
        printf(NpDec(18), GetLastError());
        return 1;
    }
    printf(NpDec(19));
    return 0;
}

//
// ============================ NPT 无痕断点 / 监视 / 无痕读（新增命令） ============================
//
// 说明：NpBreakPoint 系列命令的字符串使用明文（未进混淆表），
// 混淆表由 npobf_gen.py 生成，新增字符串如需混淆请重新生成。
//

static void PrintBp(const NPHV_BREAKPOINT_INFO_ENTRY* e)
{
    printf("  #%-3u %s addr=0x%016llX hit=%llu%s%s cpu=%u cr3=0x%llX\n",
           e->BpId,
           (e->Flags & NPHV_BP_FLAG_HALT) ? "HALT" : "STEP",
           (unsigned long long)e->Address,
           (unsigned long long)e->HitCount,
           e->Active ? "" : " [inactive]",
           e->Halted ? " [halted]" : "",
           e->LastHitCpu,
           (unsigned long long)e->LastHitCr3);
}

// 安装无痕断点：bp <name|addr> [halt|step] [oneshot]
static int CmdBp(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("usage: bp <name|addr> [halt|step] [oneshot]\n");
        return 1;
    }

    NPHV_INSTALL_BREAKPOINT_REQUEST req;
    NPHV_INSTALL_BREAKPOINT_RESPONSE resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;

    if (strncmp(argv[1], "0x", 2) == 0 || strncmp(argv[1], "0X", 2) == 0)
    {
        req.TargetAddress = strtoull(argv[1], nullptr, 0);
    }
    else
    {
        strncpy_s(req.TargetName, sizeof(req.TargetName), argv[1], _TRUNCATE);
    }

    // 默认：自动单步模式（记录 + 单步原指令 + 重新布点）
    req.Flags = 0;
    for (int i = 2; i < argc; i++)
    {
        if (_stricmp(argv[i], "halt") == 0)
        {
            req.Flags |= NPHV_BP_FLAG_HALT;
        }
        else if (_stricmp(argv[i], "oneshot") == 0)
        {
            req.Flags |= NPHV_BP_FLAG_ONESHOT;
        }
    }

    UCHAR buf[sizeof(NPHV_INSTALL_BREAKPOINT_REQUEST) + sizeof(NPHV_INSTALL_BREAKPOINT_RESPONSE)];
    memcpy(buf, &req, sizeof(req));
    ULONG returned = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_BREAKPOINT, buf, sizeof(buf), sizeof(buf), &returned))
    {
        printf("bp: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    memcpy(&resp, buf + sizeof(NPHV_INSTALL_BREAKPOINT_REQUEST), sizeof(resp));

    if (resp.Status != 0)
    {
        printf("bp: failed 0x%08X (%s)\n", resp.Status, NtStatusName(resp.Status));
        return 1;
    }
    printf("breakpoint installed: id=%u flags=0x%X\n", resp.BpId, req.Flags);
    return 0;
}

// 卸载断点：bpdel <id>
static int CmdBpDel(ULONG id)
{
    NPHV_UNINSTALL_BREAKPOINT_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.BpId = id;

    if (!Ioctl(IOCTL_NPHV_UNINSTALL_BREAKPOINT, &req, sizeof(req), 0, nullptr))
    {
        printf("bpdel: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    printf("breakpoint %lu removed\n", id);
    return 0;
}

// 列出断点：bplist
static int CmdBpList(void)
{
    NPHV_LIST_BREAKPOINTS_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG returned = 0;

    if (!Ioctl(IOCTL_NPHV_LIST_BREAKPOINTS, &resp, 0, sizeof(resp), &returned))
    {
        printf("bplist: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    printf("breakpoints: %u active (total %u)\n", resp.Count, resp.Total);
    for (ULONG i = 0; i < resp.Count; i++)
    {
        PrintBp(&resp.Entries[i]);
    }
    return 0;
}

// 继续暂停的断点：bpcont <id|all>
static int CmdBpCont(const char* arg)
{
    NPHV_CONTINUE_BREAKPOINT_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;

    if (_stricmp(arg, "all") == 0)
    {
        req.BpId = 0;
    }
    else
    {
        req.BpId = (uint32_t)strtoul(arg, nullptr, 0);
    }

    if (!Ioctl(IOCTL_NPHV_CONTINUE_BREAKPOINT, &req, sizeof(req), 0, nullptr))
    {
        printf("bpcont: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    printf("continue sent (bpId=%u)\n", req.BpId);
    return 0;
}

// 安装 NPT 监视：mon <name|addr> <r|w|rw>
static int CmdMon(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("usage: mon <name|addr> <r|w|rw>\n");
        return 1;
    }

    NPHV_INSTALL_MONITOR_REQUEST req;
    NPHV_INSTALL_MONITOR_RESPONSE resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;

    if (strncmp(argv[1], "0x", 2) == 0 || strncmp(argv[1], "0X", 2) == 0)
    {
        req.TargetAddress = strtoull(argv[1], nullptr, 0);
    }
    else
    {
        strncpy_s(req.TargetName, sizeof(req.TargetName), argv[1], _TRUNCATE);
    }

    if (strchr(argv[2], 'r') != nullptr)
    {
        req.AccessType |= NPHV_MON_ACCESS_READ;
    }
    if (strchr(argv[2], 'w') != nullptr)
    {
        req.AccessType |= NPHV_MON_ACCESS_WRITE;
    }
    if (req.AccessType == 0)
    {
        printf("mon: access must contain 'r' and/or 'w'\n");
        return 1;
    }

    UCHAR buf[sizeof(NPHV_INSTALL_MONITOR_REQUEST) + sizeof(NPHV_INSTALL_MONITOR_RESPONSE)];
    memcpy(buf, &req, sizeof(req));
    ULONG returned = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_MONITOR, buf, sizeof(buf), sizeof(buf), &returned))
    {
        printf("mon: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    memcpy(&resp, buf + sizeof(NPHV_INSTALL_MONITOR_REQUEST), sizeof(resp));

    if (resp.Status != 0)
    {
        printf("mon: failed 0x%08X (%s)\n", resp.Status, NtStatusName(resp.Status));
        return 1;
    }
    printf("monitor installed: id=%u access=0x%X\n", resp.MonitorId, req.AccessType);
    return 0;
}

// 卸载监视：mondel <id>
static int CmdMonDel(ULONG id)
{
    NPHV_UNINSTALL_MONITOR_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.MonitorId = id;

    if (!Ioctl(IOCTL_NPHV_UNINSTALL_MONITOR, &req, sizeof(req), 0, nullptr))
    {
        printf("mondel: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    printf("monitor %lu removed\n", id);
    return 0;
}

// 无痕读内存：mem <pid> <addr> <len>
static int CmdMem(int argc, char* argv[])
{
    if (argc < 4)
    {
        printf("usage: mem <pid> <addr> <len>\n");
        return 1;
    }

    NPHV_READ_MEMORY_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.ProcessId = (uint32_t)strtoul(argv[1], nullptr, 0);
    req.VirtualAddress = strtoull(argv[2], nullptr, 0);
    req.Size = (uint32_t)strtoul(argv[3], nullptr, 0);
    if (req.Size == 0 || req.Size > NPHV_MAX_MEMORY_IO)
    {
        printf("mem: len must be 1..%u\n", NPHV_MAX_MEMORY_IO);
        return 1;
    }

    UCHAR buf[sizeof(NPHV_READ_MEMORY_REQUEST) + sizeof(NPHV_READ_MEMORY_RESPONSE)];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &req, sizeof(req));
    ULONG returned = 0;
    if (!Ioctl(IOCTL_NPHV_READ_MEMORY, buf, sizeof(buf), sizeof(buf), &returned))
    {
        printf("mem: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }

    PNPHV_READ_MEMORY_RESPONSE resp =
        (PNPHV_READ_MEMORY_RESPONSE)(buf + sizeof(NPHV_READ_MEMORY_REQUEST));
    if (resp->Status != 0)
    {
        printf("mem: read failed 0x%08X (%s)\n", resp->Status, NtStatusName(resp->Status));
        return 1;
    }

    printf("read %u bytes:\n", resp->BytesRead);
    for (ULONG i = 0; i < resp->BytesRead; i++)
    {
        printf("%02X ", resp->Buffer[i]);
        if ((i & 15) == 15)
        {
            printf("\n");
        }
    }
    if ((resp->BytesRead & 15) != 0)
    {
        printf("\n");
    }
    return 0;
}

// DR 硬件断点虚拟化：drprobe on|off
static int CmdDrProbe(const char* arg)
{
    NPHV_DRPROBE_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;

    if (_stricmp(arg, "on") == 0)
    {
        req.Enable = 1;
    }
    else if (_stricmp(arg, "off") == 0)
    {
        req.Enable = 0;
    }
    else
    {
        printf("usage: drprobe on|off\n");
        return 1;
    }

    if (!Ioctl(IOCTL_NPHV_DRPROBE, &req, sizeof(req), 0, nullptr))
    {
        printf("drprobe: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    printf("drprobe %s\n", req.Enable ? "enabled" : "disabled");
    return 0;
}

// 查询假 DR 状态：drstate
static int CmdDrState(void)
{
    NPHV_DRSTATE_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG returned = 0;

    if (!Ioctl(IOCTL_NPHV_DRSTATE, &resp, 0, sizeof(resp), &returned))
    {
        printf("drstate: ioctl failed (err=%lu)\n", GetLastError());
        return 1;
    }
    if (resp.Status != 0)
    {
        printf("drstate: failed 0x%08X (%s)\n", resp.Status, NtStatusName(resp.Status));
        return 1;
    }

    printf("drprobe: %s\n", resp.DrProbeEnabled ? "enabled" : "disabled");
    printf("  fake DR0=0x%016llX DR1=0x%016llX DR2=0x%016llX DR3=0x%016llX\n",
           (unsigned long long)resp.Dr0, (unsigned long long)resp.Dr1,
           (unsigned long long)resp.Dr2, (unsigned long long)resp.Dr3);
    printf("  fake DR6=0x%016llX DR7=0x%016llX\n",
           (unsigned long long)resp.Dr6, (unsigned long long)resp.Dr7);
    printf("  pending hardware breakpoints: %u\n", resp.PendingCount);
    static const char* rwNames[] = { "execute", "write", "io", "readwrite" };
    for (ULONG i = 0; i < resp.PendingCount && i < 4; i++)
    {
        ULONG t = (ULONG)(resp.PendingTypes[i] & 3);
        printf("    [%u] addr=0x%016llX type=%s\n", i,
               (unsigned long long)resp.PendingAddresses[i],
               t < 4 ? rwNames[t] : "?");
    }
    return 0;
}

// X64DBG 调试链路隐藏：dbg hide on|off / dbg protect <pid> / dbg unprotect <pid>
//
// 窗口隐藏（R3 侧，与内核 prochide 进程枚举过滤互补）：
//   on ：枚举顶层窗口，命中【调试器进程镜像名】且标题含 x64dbg/x32dbg/
//        TitanEngine 的窗口 → 改为中性标题 + SetWindowDisplayAffinity
//        (WDA_EXCLUDEFROMCAPTURE) 防截屏；原始标题存注册表
//        HKCU\Software\NpHv\WndHide（值名=HWND）。
//   off：按注册表恢复原标题、清 affinity，并清理失效条目。
// 要点：
//   * 必须先校验进程镜像名再动窗口——Qt5QWindowIcon 是所有 Qt 程序的
//     通用类，仅凭类名会误伤其他 Qt 应用（旧实现缺陷，已修）。
//   * 窗口类名无法从外部修改（RegisterClass 后不可更名），也无需修改：
//     x64dbg 是 Qt 程序，类名本就是通用名，真正泄露身份的是标题。
//   * 只处理改名时刻已存在的顶层窗口；x64dbg 后启动或新开对话框后需重跑。
static const char* const kDbgImageNames[] = { "x64dbg.exe", "x32dbg.exe" };
static const char* const kWndRegKey = "Software\\NpHv\\WndHide";

static char WndLowerCh(char c){ return (c>='A'&&c<='Z') ? (char)(c+32) : c; }

static bool WndIsDebuggerProcess(HWND hWnd)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (!pid) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    char path[MAX_PATH * 2] = {0};
    DWORD sz = sizeof(path);
    BOOL ok = QueryFullProcessImageNameA(h, 0, path, &sz);
    CloseHandle(h);
    if (!ok) return false;
    const char* name = path;
    for (const char* q = path; *q; ++q)
        if (*q == '\\' || *q == '/') name = q + 1;
    for (const char* img : kDbgImageNames)
    {
        const char* a = name; const char* b = img;
        while (*a && *b && WndLowerCh(*a) == WndLowerCh(*b)) { ++a; ++b; }
        if (*a == 0 && *b == 0) return true;
    }
    return false;
}

static bool WndTitleLooksLikeDebugger(const char* txt)
{
    return strstr(txt, "x64dbg") || strstr(txt, "x32dbg") ||
           strstr(txt, "TitanEngine") || strstr(txt, "Scylla");
}

static void WndRegStore(HWND hWnd, const char* origTitle)
{
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, kWndRegKey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return;
    char name[32];
    snprintf(name, sizeof(name), "%llu", (unsigned long long)(uintptr_t)hWnd);
    RegSetValueExA(hKey, name, 0, REG_SZ, (const BYTE*)origTitle,
                   (DWORD)strlen(origTitle) + 1);
    RegCloseKey(hKey);
}

typedef BOOL (WINAPI* PSETAFF)(HWND, DWORD);

static PSETAFF WndGetSetAffinity()
{
    static PSETAFF p = nullptr;
    if (!p)
        p = (PSETAFF)GetProcAddress(GetModuleHandleA("user32.dll"),
                                    "SetWindowDisplayAffinity");
    return p;
}

static BOOL CALLBACK WndHideEnumProc(HWND hWnd, LPARAM lParam)
{
    if (!WndIsDebuggerProcess(hWnd)) return TRUE;       // 只动调试器自己的窗口

    char txt[256] = {0};
    GetWindowTextA(hWnd, txt, sizeof(txt));
    if (!WndTitleLooksLikeDebugger(txt)) return TRUE;   // 无特征（已改过/新会话）：跳过

    WndRegStore(hWnd, txt);                             // 先存原题再改
    SetWindowTextA(hWnd, "Calculator");
    PSETAFF p = WndGetSetAffinity();
    if (p) p(hWnd, 0x11 /*WDA_EXCLUDEFROMCAPTURE*/);
    (*(int*)(intptr_t)lParam)++;
    return TRUE;
}

static void DoWndHide(int* renamedOut)
{
    int n = 0;
    EnumWindows(WndHideEnumProc, (LPARAM)&n);
    *renamedOut = n;
}

static BOOL CALLBACK WndRestoreEnumProc(HWND hWnd, LPARAM lParam)
{
    char name[32];
    snprintf(name, sizeof(name), "%llu", (unsigned long long)(uintptr_t)hWnd);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kWndRegKey, 0, KEY_QUERY_VALUE, &hKey)
            != ERROR_SUCCESS)
        return TRUE;
    char title[256] = {0};
    DWORD sz = sizeof(title);
    LSTATUS st = RegQueryValueExA(hKey, name, nullptr, nullptr, (BYTE*)title, &sz);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS) return TRUE;

    SetWindowTextA(hWnd, title);                        // 恢复原题
    PSETAFF p = WndGetSetAffinity();
    if (p) p(hWnd, 0 /*WDA_NONE*/);
    RegDeleteKeyValueA(HKEY_CURRENT_USER, kWndRegKey, name);
    (*(int*)(intptr_t)lParam)++;
    return TRUE;
}

static void WndCleanupStaleEntries()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kWndRegKey, 0,
                      KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    DWORD idx = 0;
    for (;;)
    {
        char name[32];
        DWORD nameLen = sizeof(name);
        LONG st = RegEnumValueA(hKey, idx, name, &nameLen,
                                nullptr, nullptr, nullptr, nullptr);
        if (st != ERROR_SUCCESS) break;
        HWND hWnd = (HWND)(uintptr_t)strtoull(name, nullptr, 10);
        if (!IsWindow(hWnd))
            RegDeleteValueA(hKey, name);                // 死窗口条目：清理
        else
            ++idx;
    }
    RegCloseKey(hKey);
}

static void DoWndRestore()
{
    int n = 0;
    EnumWindows(WndRestoreEnumProc, (LPARAM)&n);
    WndCleanupStaleEntries();
    if (n > 0)
        printf("window restore: %d window(s) restored\n", n);
}
static int CmdDbg(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("usage: dbg hide on|off\n"
               "       dbg protect <pid>\n"
               "       dbg unprotect <pid>\n"
               "       dbg mode white|black\n");
        return 1;
    }

    if (strcmp(argv[1], "hide") == 0 && argc >= 3)
    {
        // Try hypercall first (deviceless)
        bool enable = (strcmp(argv[2], "on")==0);
        if(HcDbgHide(enable)){
            printf("debug-hide %s (via hypercall)\n", enable?"enabled":"disabled");
            if (enable) {
                int renamed = 0;
                DoWndHide(&renamed);
                printf("window hide: %d window(s) masked "
                       "(title->Calculator + exclude-from-capture)\n", renamed);
                if (renamed == 0)
                    printf("  note: no debugger windows found; re-run after x64dbg starts\n");
            } else {
                DoWndRestore();
            }
            return 0;
        }
        NPHV_DEBUG_HIDE_REQUEST req;
        memset(&req, 0, sizeof(req));
        req.Version = NPHV_PROTOCOL_VERSION;

        if (strcmp(argv[2], "on") == 0)
        {
            req.Enable = 1;
        }
        else if (strcmp(argv[2], "off") == 0)
        {
            req.Enable = 0;
        }
        else
        {
            printf("usage: dbg hide on|off\n");
            return 1;
        }

        if (!Ioctl(IOCTL_NPHV_DEBUG_HIDE, &req, sizeof(req), 0, nullptr))
        {
            printf("dbg hide: ioctl failed (err=%lu)\n", GetLastError());
            return 1;
        }
        printf("debug-hide %s\n", req.Enable ? "enabled" : "disabled");
        if (req.Enable)
        {
            int renamed = 0;
            DoWndHide(&renamed);
            printf("window hide: %d window(s) masked "
                   "(title->Calculator + exclude-from-capture)\n", renamed);
            if (renamed == 0)
                printf("  note: no debugger windows found; re-run after x64dbg starts\n");
        }
        else
        {
            DoWndRestore();
        }
        return 0;
    }

    if ((strcmp(argv[1], "protect") == 0 || strcmp(argv[1], "unprotect") == 0) &&
        argc >= 3)
    {
        NPHV_DEBUG_PROTECT_REQUEST req;
        memset(&req, 0, sizeof(req));
        req.Version = NPHV_PROTOCOL_VERSION;
        req.ProcessId = (uint32_t)strtoul(argv[2], nullptr, 0);
        req.Protect = (strcmp(argv[1], "protect") == 0) ? 1 : 0;

        if (!Ioctl(IOCTL_NPHV_DEBUG_PROTECT, &req, sizeof(req), 0, nullptr))
        {
            printf("dbg %s: ioctl failed (err=%lu)\n", argv[1], GetLastError());
            return 1;
        }
        printf("%s pid=%u\n", req.Protect ? "protected" : "unprotected", req.ProcessId);
        return 0;
    }

    if (strcmp(argv[1], "mode") == 0)
    {
        //
        // dbg mode white|black
        //   white：白名单（默认）——仅注册的 PID 隐藏
        //   black：黑名单——除注册的 PID 外，所有进程都隐藏
        //
        if (argc < 3)
        {
            printf("usage: dbg mode white|black\n");
            return 1;
        }

        NPHV_DEBUG_MODE_REQUEST req;
        memset(&req, 0, sizeof(req));
        req.Version = NPHV_PROTOCOL_VERSION;
        if (strcmp(argv[2], "black") == 0)
        {
            req.Mode = NPHV_DEBUG_MODE_BLACKLIST;
        }
        else if (strcmp(argv[2], "white") == 0)
        {
            req.Mode = NPHV_DEBUG_MODE_WHITELIST;
        }
        else
        {
            printf("usage: dbg mode white|black\n");
            return 1;
        }

        if (!Ioctl(IOCTL_NPHV_DEBUG_MODE, &req, sizeof(req), 0, nullptr))
        {
            printf("dbg mode: ioctl failed (err=%lu)\n", GetLastError());
            return 1;
        }
        printf("debug-hide mode = %s\n",
               req.Mode == NPHV_DEBUG_MODE_BLACKLIST ? "blacklist (hide all except pid)" :
                                                       "whitelist");
        return 0;
    }

    printf("unknown dbg subcommand\n");
    return 1;
}

static int CmdProcHide(int argc, char* argv[])
{
    if(argc < 1){
        printf("usage: prochide on|off\n       prochide add <name>\n       prochide del <name>\n       prochide clear\n       prochide list\n       prochide watch <name>    (viewer exempt from filtering)\n       prochide unwatch <name>\n");
        return 1;
    }
    if(strcmp(argv[0],"on")==0){
        NPHV_PROCESS_HIDE_REQUEST req; memset(&req,0,sizeof(req)); req.Version=NPHV_PROTOCOL_VERSION; req.Enable=1;
        if(!Ioctl(IOCTL_NPHV_PROCESS_HIDE, &req, sizeof(req),0,nullptr)){ printf("prochide on: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide enabled\n"); return 0;
    }
    if(strcmp(argv[0],"off")==0){
        NPHV_PROCESS_HIDE_REQUEST req; memset(&req,0,sizeof(req)); req.Version=NPHV_PROTOCOL_VERSION; req.Enable=0;
        if(!Ioctl(IOCTL_NPHV_PROCESS_HIDE, &req, sizeof(req),0,nullptr)){ printf("prochide off: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide disabled\n"); return 0;
    }
    if(strcmp(argv[0],"add")==0 && argc>=2){
        NPHV_PROCESS_HIDE_NAME_REQUEST req; memset(&req,0,sizeof(req)); req.Version=NPHV_PROTOCOL_VERSION;
        // Convert to wchar
        MultiByteToWideChar(CP_ACP,0,argv[1],-1,req.Name,64);
        if(!Ioctl(IOCTL_NPHV_PROCESS_HIDE_ADD, &req, sizeof(req),0,nullptr)){ printf("prochide add: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide add %s ok\n", argv[1]); return 0;
    }
    if((strcmp(argv[0],"del")==0 || strcmp(argv[0],"remove")==0) && argc>=2){
        NPHV_PROCESS_HIDE_NAME_REQUEST req; memset(&req,0,sizeof(req)); req.Version=NPHV_PROTOCOL_VERSION;
        MultiByteToWideChar(CP_ACP,0,argv[1],-1,req.Name,64);
        if(!Ioctl(IOCTL_NPHV_PROCESS_HIDE_REMOVE, &req, sizeof(req),0,nullptr)){ printf("prochide del: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide del %s ok\n", argv[1]); return 0;
    }
    if(strcmp(argv[0],"clear")==0){
        if(!Ioctl(IOCTL_NPHV_PROCESS_HIDE_CLEAR, nullptr,0,0,nullptr)){ printf("prochide clear: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide cleared\n"); return 0;
    }
    if(strcmp(argv[0],"list")==0){
        NPHV_PROCESS_HIDE_LIST_RESPONSE resp; memset(&resp,0,sizeof(resp));
        ULONG ret=0;
        if(!Ioctl(IOCTL_NPHV_PROCESS_HIDE_LIST, &resp,0,sizeof(resp),&ret)){ printf("prochide list: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide: %s count=%lu\n", resp.Enabled?"enabled":"disabled", resp.Count);
        for(ULONG i=0;i<resp.Count && i<16;i++){
            char mb[128]; WideCharToMultiByte(CP_ACP,0,resp.Names[i],-1,mb,128,nullptr,nullptr);
            printf("  [%lu] %s\n", i, mb);
        }
        // 查看者豁免名单（名单内进程枚举时不过滤，自家调试器可见全部）
        NPHV_PROCESS_HIDE_LIST_RESPONSE wresp; memset(&wresp,0,sizeof(wresp));
        if(Ioctl(IOCTL_NPHV_PROCESS_WATCH_LIST, &wresp,0,sizeof(wresp),&ret)){
            printf("watchers: count=%lu (no filter applied for these)\n", wresp.Count);
            for(ULONG i=0;i<wresp.Count && i<16;i++){
                char mb[128]; WideCharToMultiByte(CP_ACP,0,wresp.Names[i],-1,mb,128,nullptr,nullptr);
                printf("  [W%lu] %s\n", i, mb);
            }
        }
        return 0;
    }
    if(strcmp(argv[0],"watch")==0 && argc>=2){
        NPHV_PROCESS_HIDE_NAME_REQUEST req; memset(&req,0,sizeof(req)); req.Version=NPHV_PROTOCOL_VERSION;
        MultiByteToWideChar(CP_ACP,0,argv[1],-1,req.Name,64);
        if(!Ioctl(IOCTL_NPHV_PROCESS_WATCH_ADD, &req, sizeof(req),0,nullptr)){ printf("prochide watch: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide watch %s ok\n", argv[1]); return 0;
    }
    if(strcmp(argv[0],"unwatch")==0 && argc>=2){
        NPHV_PROCESS_HIDE_NAME_REQUEST req; memset(&req,0,sizeof(req)); req.Version=NPHV_PROTOCOL_VERSION;
        MultiByteToWideChar(CP_ACP,0,argv[1],-1,req.Name,64);
        if(!Ioctl(IOCTL_NPHV_PROCESS_WATCH_REMOVE, &req, sizeof(req),0,nullptr)){ printf("prochide unwatch: ioctl failed (err=%lu)\n", GetLastError()); return 1; }
        printf("prochide unwatch %s ok\n", argv[1]); return 0;
    }
    printf("unknown prochide subcommand\n"); return 1;
}

static int CmdDemo(void)
{
    printf(NpDec(20));

    // 1. 状态
    CmdStatus();

    // 2. 安装 LogOnly Hook 到 NtQuerySystemInformation
    printf(NpDec(21));
    NPHV_INSTALL_HOOK_REQUEST req;
    NPHV_INSTALL_HOOK_RESPONSE resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.Action = NpHookActionLogOnly;
    strncpy_s(req.TargetName, sizeof(req.TargetName), NpDec(22), _TRUNCATE);

    UCHAR buf[sizeof(NPHV_INSTALL_HOOK_REQUEST) + sizeof(NPHV_INSTALL_HOOK_RESPONSE)];
    memcpy(buf, &req, sizeof(req));
    ULONG returned = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_HOOK, buf,
               sizeof(buf), sizeof(buf), &returned))
    {
        printf(NpDec(11), GetLastError());
        return 1;
    }
    memcpy(&resp, buf + sizeof(NPHV_INSTALL_HOOK_REQUEST), sizeof(resp));
    if (resp.Status != 0)
    {
        printf(NpDec(12), NtStatusName(resp.Status), resp.Status);
        return 1;
    }
    printf(NpDec(23), resp.HookId);

    // 3. 触发几次（用户态调用 ntdll!NtQuerySystemInformation）
    printf(NpDec(24));
    {
        HMODULE ntdll = LoadLibraryA(NpDec(25));
        PFN_NTQSI pNtQSI = (PFN_NTQSI)GetProcAddress(ntdll, NpDec(22));
        if (pNtQSI != nullptr)
        {
            UCHAR sysinfo[1024];
            ULONG retLen = 0;
            for (int i = 0; i < 5; i++)
            {
                NTSTATUS st = pNtQSI(5 /*SystemProcessInformation*/,
                                     sysinfo, sizeof(sysinfo), &retLen);
                printf(NpDec(26), i + 1, (ULONG)st);
            }
        }
        else
        {
            printf(NpDec(27));
        }
    }

    // 4. 状态（Hook 计数应 >= 1）
    printf(NpDec(28));
    CmdStatus();

    // 5. 卸载
    printf(NpDec(29));
    CmdUnhook(resp.HookId);
    CmdStatus();

    printf(NpDec(30));
    return 0;
}

// ============================ 新架构 CLI（P2/P4/P5/P0） ============================

static int HexToBytes(const char* s, uint8_t* out, size_t max)
{
    size_t n = 0;
    while (*s && n < max)
    {
        while (*s == ' ' || *s == '\t' || *s == ',' || *s == ':') s++;
        if (!*s) break;
        int hi = -1, lo = -1;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        hi = nib(*s);
        if (hi < 0) return -1;
        s++;
        if (*s && nib(*s) >= 0)
        {
            lo = nib(*s);
            s++;
        }
        out[n++] = (uint8_t)((hi << 4) | (lo < 0 ? 0 : lo));
    }
    return (int)n;
}

static int CmdSyscheck(void)
{
    NPHV_SYSCALL_PRECHECK_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_SYSCALL_PRECHECK, &resp, 0, sizeof(resp), &ret))
    {
        printf("syscheck failed: err=%lu\n", GetLastError());
        return 1;
    }
    printf("syscall precheck: all=%s table=0x%llx module=0x%llx kind=%uB\n",
           resp.AllPassed ? "PASS" : "FAIL",
           (unsigned long long)resp.ServiceTable,
           (unsigned long long)resp.ModuleBase,
           resp.Is4B ? 4 : 8);
    for (ULONG i = 0; i < resp.Count && i < NPHV_SYSCALL_PRECHECK_COUNT; i++)
    {
        printf("  %-32s syscall=%-6lu addr=0x%-16llx %s\n",
               resp.Entries[i].Name,
               (unsigned long)resp.Entries[i].Syscall,
               (unsigned long long)resp.Entries[i].Address,
               resp.Entries[i].Resolved ? "OK" : "MISSING");
    }
    return resp.AllPassed ? 0 : 1;
}

// ============================ GUI 模式（无参数启动） ============================
// 双模式：带命令行参数 → 原 CLI（脚本兼容）；无参数 → 图形界面。
// 纯 Win32 实现（comctl32/gdi32），不引入任何新依赖。

enum {
    IDC_TAB = 200, IDC_LOG, IDC_LOG_TOGGLE,
    // 状态
    IDC_ST_REFRESH, IDC_ST_TEXT,
    // 断点
    IDC_BP_TARGET, IDC_BP_HALT, IDC_BP_ONESHOT, IDC_BP_INSTALL,
    IDC_BP_LIST, IDC_BP_REFRESH, IDC_BP_DELETE, IDC_BP_CONTSEL, IDC_BP_CONTALL,
    // 监视
    IDC_MON_TARGET, IDC_MON_R, IDC_MON_W, IDC_MON_INSTALL,
    IDC_MON_ID, IDC_MON_DELETE,
    // 内存
    IDC_MEM_PID, IDC_MEM_ADDR, IDC_MEM_LEN, IDC_MEM_READ, IDC_MEM_DUMP,
    // 调试隐藏
    IDC_DBG_ON, IDC_DBG_OFF, IDC_DR_ON, IDC_DR_OFF, IDC_DRSTATE_BTN,
    IDC_DBG_PID, IDC_DBG_PROTECT, IDC_DBG_UNPROTECT,
    IDC_MODE_WHITE, IDC_MODE_BLACK, IDC_MODE_APPLY,
    // 进程隐藏
    IDC_PH_ON, IDC_PH_OFF, IDC_PH_NAME, IDC_PH_ADD, IDC_PH_DEL,
    IDC_PH_CLEAR, IDC_PH_LIST, IDC_PH_WATCH_ADD, IDC_PH_WATCH_DEL,
    // Hook
    IDC_HK_TARGET, IDC_HK_ACTION, IDC_HK_RET, IDC_HK_INSTALL,
    IDC_HK_ID, IDC_HK_UNINSTALL, IDC_HK_UNALL,
    IDC_DRV_INSTALL, IDC_DRV_UNINSTALL, IDC_DRV_STATUS, IDC_DRV_LOG,
};

#define GUI_PANELS 8        // 状态/断点/监视/内存/调试隐藏/进程隐藏/Hook

static void GuiOnCommand(int id, int code);   // fwd：按钮命令分发

static HWND g_hMain = nullptr, g_hTab = nullptr, g_hLog = nullptr, g_hLogToggle = nullptr;
static HFONT g_hFont = nullptr, g_hFontMono = nullptr;
static HBRUSH g_hBrBk = nullptr;
static HWND g_Panel[GUI_PANELS];
static HWND g_hCtlParent = nullptr;     // 当前构建页签：新控件的父窗口

// 控件查找：控件挂在各页签容器下，遍历容器定位（主窗口直挂的也能找到）
static HWND Ctrl(int id)
{
    HWND h = GetDlgItem(g_hMain, id);
    if (h) return h;
    for (int i = 0; i < GUI_PANELS; i++)
    {
        h = GetDlgItem(g_Panel[i], id);
        if (h) return h;
    }
    return nullptr;
}
static bool Chk(int id)
{
    HWND h = Ctrl(id);
    return h && SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

static void GuiAppendLog(const wchar_t* line)
{
    if (!g_hLog) return;
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line);
}

static void GuiLogF(const wchar_t* fmt, ...)
{
    wchar_t buf[1200];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 1100, fmt, ap);
    buf[1100] = 0;
    va_end(ap);
    size_t l = wcslen(buf);
    if (l + 2 < 1200) { buf[l] = '\r'; buf[l+1] = '\n'; buf[l+2] = 0; }
    GuiAppendLog(buf);
}

static void W2A(const wchar_t* w, char* out, size_t cb)
{
    WideCharToMultiByte(CP_ACP, 0, w, -1, out, (int)cb, nullptr, nullptr);
}
static void A2W(const char* a, wchar_t* out, size_t cw)
{
    MultiByteToWideChar(CP_ACP, 0, a, -1, out, (int)cw);
}

// 十六进制解析：接受可选 0x 前缀，全串必须是合法 hex
static bool ParseHex64(const wchar_t* s, unsigned long long& out)
{
    if (!s || !*s) return false;
    const wchar_t* p = s;
    if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) p += 2;
    if (!*p) return false;
    unsigned long long v = 0; int n = 0;
    for (; *p; ++p, ++n)
    {
        wchar_t c = *p;
        int d;
        if (c >= L'0' && c <= L'9') d = c - L'0';
        else if (c >= L'a' && c <= L'f') d = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') d = c - L'A' + 10;
        else return false;
        v = v * 16 + (unsigned)d;
    }
    out = v;
    return n >= 1;
}

// 目标解析：像地址（≥8 位 hex）按地址，否则按函数名
static bool GuiParseTarget(HWND hEdit, char* nameOut, size_t cbName,
                           unsigned long long& addrOut, bool& isAddr)
{
    wchar_t txt[128] = {0};
    GetWindowTextW(hEdit, txt, 128);
    if (!txt[0]) return false;
    unsigned long long v;
    if (wcslen(txt) >= 8 && ParseHex64(txt, v))
    {
        isAddr = true; addrOut = v; return true;
    }
    isAddr = false; W2A(txt, nameOut, cbName); return nameOut[0] != 0;
}

static HWND MkCtl(DWORD exStyle, const wchar_t* cls, const wchar_t* text,
                  DWORD style, int x, int y, int w, int h, int id)
{
    //
    // 控件父窗口 = 当前构建的页签容器（g_hCtlParent）。
    // 旧实现误挂主窗口 → 所有页签控件叠加显示（已修复的布局 bug）。
    //
    return CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style,
                           x, y, w, h, g_hCtlParent, (HMENU)(intptr_t)id,
                           GetModuleHandleW(nullptr), nullptr);
}

// ---- ListView 辅助 ----
static void LvAddCol(HWND lv, int idx, int w, const wchar_t* title)
{
    LVCOLUMNW c;
    memset(&c, 0, sizeof(c));
    c.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    c.cx = w; c.pszText = (LPWSTR)title; c.iSubItem = idx;
    SendMessageW(lv, LVM_INSERTCOLUMNW, idx, (LPARAM)&c);
}
static int LvAddRow(HWND lv, const wchar_t* c0)
{
    LVITEMW it;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT; it.pszText = (LPWSTR)c0;
    it.iItem = (int)SendMessageW(lv, LVM_GETITEMCOUNT, 0, 0);
    return (int)SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&it);
}
static void LvSet(HWND lv, int row, int col, const wchar_t* txt)
{
    LVITEMW it;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT; it.iItem = row; it.iSubItem = col;
    it.pszText = (LPWSTR)txt;
    SendMessageW(lv, LVM_SETITEMW, 0, (LPARAM)&it);
}
static int LvSel(HWND lv)
{
    return (int)SendMessageW(lv, LVM_GETNEXTITEM, (WPARAM)-1,
                             MAKELPARAM(LVNI_SELECTED, 0));
}
static bool LvText(HWND lv, int row, int col, wchar_t* out, int cw)
{
    LVITEMW it;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT; it.iItem = row; it.iSubItem = col;
    it.pszText = out; it.cchTextMax = cw;
    return SendMessageW(lv, LVM_GETITEMW, 0, (LPARAM)&it) != 0;
}

static const wchar_t* NtStatusNameW(ULONG st)
{
    static wchar_t unk[32];
    const char* a = NtStatusName(st);
    if (strcmp(a, "STATUS_?") != 0)
    {
        static wchar_t named[64];
        A2W(a, named, 64);
        return named;
    }
    swprintf(unk, 32, L"0x%08X", st);
    return unk;
}

// ---- 各功能动作 ----

static void GuiDoRefreshStatus()
{
    NPHV_STATUS_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG ret = 0;
    wchar_t txt[512];
    CtlTrace("RefreshStatus before QUERY_STATUS");
    bool hcOk=false; NPHV_STATUS_RESPONSE hc{}; if(HcQueryStatus(&hc,sizeof(hc))){ resp=hc; hcOk=true; }
    if (!hcOk && !Ioctl(IOCTL_NPHV_QUERY_STATUS, &resp, 0, sizeof(resp), &ret))
    {
        CtlTrace("RefreshStatus QUERY_STATUS failed");
        swprintf(txt, 512,
                 L"Hypervisor 状态：无法连接设备 (err=%lu)\r\n"
                 L"请先在测试机执行: sc start NpHv", GetLastError());
        SetWindowTextW(Ctrl(IDC_ST_TEXT), txt);
        return;
    }
    CtlTrace("RefreshStatus after QUERY_STATUS");
    swprintf(txt, 512,
             L"协议版本      : %lu\r\n"
             L"Hypervisor    : %s\r\n"
             L"CPU 数量      : %lu\r\n"
             L"活动 Hook 数  : %lu\r\n"
             L"驱动自隐藏    : %s\r\n",
             resp.Version,
             resp.HypervisorRunning ? L"运行中 ✔" : L"未运行 ✘",
             resp.ProcessorCount,
             resp.ActiveHookCount,
             (resp.Flags & NPHV_FLAG_SELF_HIDE) ? L"enabled" : L"disabled");

    NPHV_LSTAR_STATUS_RESPONSE ls;
    memset(&ls, 0, sizeof(ls));
    ULONG lret = 0;
    CtlTrace("RefreshStatus before LSTAR_STATUS");
    if (Ioctl(IOCTL_NPHV_LSTAR_STATUS, &ls, 0, sizeof(ls), &lret))
    {
        CtlTrace("RefreshStatus after LSTAR_STATUS ok");
        wchar_t extra[256];
        swprintf(extra, 256,
                 L"\r\nLSTAR         : %s (orig=0x%llX tramp=0x%llX, %lu 拦截项)",
                 ls.Hooked ? L"接管" : L"未接管",
                 (unsigned long long)ls.OrigLstar,
                 (unsigned long long)ls.Trampoline,
                 (unsigned long)ls.InterceptCount);
        wcscat(txt, extra);
    }
    else
    {
        CtlTrace("RefreshStatus LSTAR_STATUS failed");
    }
    SetWindowTextW(Ctrl(IDC_ST_TEXT), txt);
}

static void GuiDoBpInstall()
{
    NPHV_INSTALL_BREAKPOINT_REQUEST req;
    NPHV_INSTALL_BREAKPOINT_RESPONSE resp;
    memset(&req, 0, sizeof(req)); memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;
    bool isAddr = false;
    if (!GuiParseTarget(Ctrl(IDC_BP_TARGET),
                        req.TargetName, sizeof(req.TargetName),
                        req.TargetAddress, isAddr))
    {
        GuiLogF(L"[bp] 请输入函数名或十六进制地址"); return;
    }
    if (Chk(IDC_BP_HALT))
        req.Flags |= NPHV_BP_FLAG_HALT;
    if (Chk(IDC_BP_ONESHOT))
        req.Flags |= NPHV_BP_FLAG_ONESHOT;

    UCHAR buf[sizeof(req) + sizeof(resp)];
    memcpy(buf, &req, sizeof(req));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_BREAKPOINT, buf, sizeof(buf), sizeof(buf), &ret))
    {
        GuiLogF(L"[bp] ioctl failed (err=%lu)", GetLastError()); return;
    }
    memcpy(&resp, buf + sizeof(req), sizeof(resp));
    if (resp.Status != 0)
    {
        GuiLogF(L"[bp] install failed: %s (%08X)",
                NtStatusNameW(resp.Status), resp.Status);
        return;
    }
    GuiLogF(L"[bp] installed id=%u %s=0x%llX flags=0x%X",
            resp.BpId, isAddr ? L"addr" : L"name",
            (unsigned long long)(isAddr ? req.TargetAddress : 0), req.Flags);
}

static void GuiDoBpRefresh()
{
    HWND lv = Ctrl(IDC_BP_LIST);
    SendMessageW(lv, LVM_DELETEALLITEMS, 0, 0);
    NPHV_LIST_BREAKPOINTS_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_LIST_BREAKPOINTS, &resp, 0, sizeof(resp), &ret))
    {
        GuiLogF(L"[bp] list ioctl failed (err=%lu)", GetLastError()); return;
    }
    for (ULONG i = 0; i < resp.Count && i < NPHV_MAX_BREAKPOINTS; i++)
    {
        const NPHV_BREAKPOINT_INFO_ENTRY& e = resp.Entries[i];
        wchar_t c0[16], c1[24], c2[24], c3[16], c4[12], c5[20], c6[12];
        swprintf(c0, 16, L"%u", e.BpId);
        swprintf(c1, 24, L"0x%llX", (unsigned long long)e.Address);
        swprintf(c2, 24, L"%s%s%s",
                 (e.Flags & NPHV_BP_FLAG_DEBUGGER) ? L"DBG " : L"",
                 (e.Flags & NPHV_BP_FLAG_HALT) ? L"HALT " : L"",
                 (e.Flags & NPHV_BP_FLAG_ONESHOT) ? L"1SHOT" : L"STEP");
        swprintf(c3, 16, L"%llu", (unsigned long long)e.HitCount);
        swprintf(c4, 12, L"%s", e.Halted ? L"暂停" : L"-");
        swprintf(c5, 20, L"0x%llX", (unsigned long long)e.LastHitRip);
        swprintf(c6, 12, L"%u", e.LastHitCpu);
        int row = LvAddRow(lv, c0);
        LvSet(lv, row, 1, c1); LvSet(lv, row, 2, c2); LvSet(lv, row, 3, c3);
        LvSet(lv, row, 4, c4); LvSet(lv, row, 5, c5); LvSet(lv, row, 6, c6);
    }
}

static void GuiDoBpDelete()
{
    HWND lv = Ctrl(IDC_BP_LIST);
    int sel = LvSel(lv);
    if (sel < 0) { GuiLogF(L"[bp] 请先选中一行"); return; }
    wchar_t idt[16]; LvText(lv, sel, 0, idt, 16);
    NPHV_UNINSTALL_BREAKPOINT_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.BpId = (uint32_t)wcstoul(idt, nullptr, 10);
    if (!Ioctl(IOCTL_NPHV_UNINSTALL_BREAKPOINT, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[bp] delete ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[bp] deleted id=%u", req.BpId);
    GuiDoBpRefresh();
}

static void GuiDoBpCont(unsigned idOr0)
{
    NPHV_CONTINUE_BREAKPOINT_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.BpId = idOr0;
    if (!Ioctl(IOCTL_NPHV_CONTINUE_BREAKPOINT, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[bp] continue ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[bp] continue %s sent", idOr0 ? L"" : L"(all)");
    GuiDoBpRefresh();
}

static void GuiDoMonInstall()
{
    NPHV_INSTALL_MONITOR_REQUEST req;
    NPHV_INSTALL_MONITOR_RESPONSE resp;
    memset(&req, 0, sizeof(req)); memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;
    bool isAddr = false;
    if (!GuiParseTarget(Ctrl(IDC_MON_TARGET),
                        req.TargetName, sizeof(req.TargetName),
                        req.TargetAddress, isAddr))
    {
        GuiLogF(L"[mon] 请输入函数名或十六进制地址"); return;
    }
    if (Chk(IDC_MON_R))
        req.AccessType |= NPHV_MON_ACCESS_READ;
    if (Chk(IDC_MON_W))
        req.AccessType |= NPHV_MON_ACCESS_WRITE;
    if (!req.AccessType)
    {
        GuiLogF(L"[mon] 请选择访问类型（读/写）"); return;
    }
    UCHAR buf[sizeof(req) + sizeof(resp)];
    memcpy(buf, &req, sizeof(req));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_MONITOR, buf, sizeof(buf), sizeof(buf), &ret))
    {
        GuiLogF(L"[mon] ioctl failed (err=%lu)", GetLastError()); return;
    }
    memcpy(&resp, buf + sizeof(req), sizeof(resp));
    if (resp.Status != 0)
    {
        GuiLogF(L"[mon] install failed: %s (%08X)",
                NtStatusNameW(resp.Status), resp.Status);
        return;
    }
    GuiLogF(L"[mon] installed id=%u access=%s",
            resp.MonitorId,
            req.AccessType == 3 ? L"RW" :
            (req.AccessType & 1) ? L"R" : L"W");
}

static void GuiDoMonDelete()
{
    wchar_t idt[16] = {0};
    GetWindowTextW(Ctrl(IDC_MON_ID), idt, 16);
    uint32_t id = (uint32_t)wcstoul(idt, nullptr, 10);
    if (!id) { GuiLogF(L"[mon] 请输入要卸载的监视 ID"); return; }
    NPHV_UNINSTALL_MONITOR_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.MonitorId = id;
    if (!Ioctl(IOCTL_NPHV_UNINSTALL_MONITOR, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[mon] delete ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[mon] deleted id=%u", id);
}

static void GuiDoMemRead()
{
    wchar_t tPid[16] = {0}, tAddr[40] = {0}, tLen[16] = {0};
    GetWindowTextW(Ctrl(IDC_MEM_PID), tPid, 16);
    GetWindowTextW(Ctrl(IDC_MEM_ADDR), tAddr, 40);
    GetWindowTextW(Ctrl(IDC_MEM_LEN), tLen, 16);
    char pidA[24];
    W2A(tPid, pidA, sizeof(pidA));
    unsigned long long pid = strtoull(pidA, nullptr, 10);
    unsigned long long addr = 0, len = 64;
    if (!pid) { GuiLogF(L"[mem] PID 无效"); return; }
    if (!ParseHex64(tAddr, addr)) { GuiLogF(L"[mem] 地址无效（hex）"); return; }
    if (!(tLen[0] && ParseHex64(tLen, len))) len = 64;
    if (len > NPHV_MAX_MEMORY_IO) len = NPHV_MAX_MEMORY_IO;

    NPHV_READ_MEMORY_REQUEST req;
    NPHV_READ_MEMORY_RESPONSE resp;
    memset(&req, 0, sizeof(req)); memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.ProcessId = (uint32_t)pid;
    req.VirtualAddress = addr;
    req.Size = (uint32_t)len;
    UCHAR buf[sizeof(req) + sizeof(resp)];
    memcpy(buf, &req, sizeof(req));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_READ_MEMORY, buf, sizeof(buf), sizeof(buf), &ret))
    {
        GuiLogF(L"[mem] ioctl failed (err=%lu)", GetLastError()); return;
    }
    memcpy(&resp, buf + sizeof(req), sizeof(resp));
    if (resp.Status != 0)
    {
        GuiLogF(L"[mem] read failed: %s (%08X)",
                NtStatusNameW(resp.Status), resp.Status);
        return;
    }
    GuiLogF(L"[mem] read %lu bytes @ 0x%llX (pid %llu)",
            resp.BytesRead, addr, pid);

    // hexdump → 内存页签的只读框
    wchar_t line[128], all[16384];
    all[0] = 0;
    for (ULONG off = 0; off < resp.BytesRead; off += 16)
    {
        wchar_t hex[64]; int hx = 0;
        wchar_t asc[20]; int ac = 0;
        for (ULONG j = 0; j < 16; ++j)
        {
            if (off + j < resp.BytesRead)
            {
                hx += swprintf(hex + hx, 64 - hx, L"%02X ", resp.Buffer[off+j]);
                wchar_t ch = resp.Buffer[off+j];
                asc[ac++] = (ch >= 0x20 && ch < 0x7F) ? ch : L'.';
            }
            else
            {
                hx += swprintf(hex + hx, 64 - hx, L"   ");
                asc[ac++] = L' ';
            }
            if (j == 7) { hex[hx++] = L' '; asc[ac++] = L' '; }
        }
        asc[ac] = 0;
        swprintf(line, 128, L"%04X  %s %s\r\n", (unsigned)off, hex, asc);
        wcscat(all, line);
    }
    SetWindowTextW(Ctrl(IDC_MEM_DUMP), all);
}

static void GuiDoPhOnOff(bool on);

static void GuiDoDbgHide(BOOL enable)
{
    NPHV_DEBUG_HIDE_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.Enable = enable ? 1 : 0;
    CtlTrace(enable ? "DbgHide before ioctl ON" : "DbgHide before ioctl OFF");
        // Hypercall first (deviceless)
    if (HcDbgHide(enable != FALSE)) {
        CtlTrace("DbgHide hypercall ok");
        GuiLogF(L"[dbg] debug-hide %s (hypercall)", enable ? L"enabled" : L"disabled");
        if (enable) {
            // Same linkage as device path: prochide + window masking
            GuiDoPhOnOff(true);
            GuiLogF(L"[dbg] prochide auto-enabled (Task Manager hide)");
            int renamed = 0;
            DoWndHide(&renamed);
            GuiLogF(L"[dbg] window hide: %d masked%s", renamed,
                    renamed ? L"" : L"（x64dbg 未启动？启动后重跑本开关即可）");
        } else {
            GuiDoPhOnOff(false);
            GuiLogF(L"[dbg] prochide auto-disabled");
            DoWndRestore();
            GuiLogF(L"[dbg] window titles restored");
        }
        return;
    }
    CtlTrace("DbgHide hypercall miss, fallback device");
if (!Ioctl(IOCTL_NPHV_DEBUG_HIDE, &req, sizeof(req), 0, nullptr))
    {
        CtlTrace("DbgHide ioctl failed");
        GuiLogF(L"[dbg] ioctl failed (err=%lu)", GetLastError()); return;
    }
    CtlTrace("DbgHide ioctl ok");
    GuiLogF(L"[dbg] debug-hide %s", enable ? L"enabled ✔" : L"disabled");
    if (enable)
    {
        // 联动：调试隐藏开启时同时启用进程隐藏，任务管理器等枚举
        // 看不到 x64dbg（x64dbg 自身在查看者豁免名单，附加窗口不受影响）。
        GuiDoPhOnOff(true);
        GuiLogF(L"[dbg] prochide auto-enabled (Task Manager hide)");
        int renamed = 0;
        DoWndHide(&renamed);
        CtlTrace("DbgHide after DoWndHide");
        GuiLogF(L"[dbg] window hide: %d masked%s", renamed,
                renamed ? L"" : L"（x64dbg 未启动？启动后重跑本开关即可）");
    }
    else
    {
        GuiDoPhOnOff(false);
        GuiLogF(L"[dbg] prochide auto-disabled");
        DoWndRestore();
        CtlTrace("DbgHide after DoWndRestore");
        GuiLogF(L"[dbg] window titles restored");
    }
}

static void GuiDoDrProbe(bool on)
{
    NPHV_DRPROBE_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.Enable = on ? 1 : 0;
    if (!Ioctl(IOCTL_NPHV_DRPROBE, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[dr] ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[dr] drprobe %s", on ? L"enabled" : L"disabled");
}

static void GuiDoDrState()
{
    NPHV_DRSTATE_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_DRSTATE, &resp, 0, sizeof(resp), &ret))
    {
        GuiLogF(L"[dr] state ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[dr] probe=%s DR0=%llX DR1=%llX DR2=%llX DR3=%llX pending=%u",
            resp.DrProbeEnabled ? L"on" : L"off",
            resp.Dr0, resp.Dr1, resp.Dr2, resp.Dr3, resp.PendingCount);
    static const wchar_t* rw[] = { L"exec", L"write", L"io", L"rw" };
    for (ULONG i = 0; i < resp.PendingCount && i < 4; i++)
        GuiLogF(L"   [%u] 0x%llX (%s)", i,
                (unsigned long long)resp.PendingAddresses[i],
                rw[resp.PendingTypes[i] & 3]);
}

static void GuiDoProtect(BOOL protect)
{
    wchar_t tPid[16] = {0};
    GetWindowTextW(Ctrl(IDC_DBG_PID), tPid, 16);
    uint32_t pid = (uint32_t)wcstoul(tPid, nullptr, 10);
    if (!pid) { GuiLogF(L"[dbg] PID 无效"); return; }
    NPHV_DEBUG_PROTECT_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.ProcessId = pid;
    req.Protect = protect ? 1 : 0;
    if (HcDbgProtect(pid, protect != FALSE)) {
        GuiLogF(L"[dbg] %s pid=%u (hypercall)", protect ? L"protected" : L"unprotected", pid);
        return;
    }
    if (!Ioctl(IOCTL_NPHV_DEBUG_PROTECT, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[dbg] protect ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[dbg] %s pid=%u", protect ? L"protected" : L"unprotected", pid);
}

static void GuiDoMode(BOOL black)
{
    NPHV_DEBUG_MODE_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.Mode = black ? NPHV_DEBUG_MODE_BLACKLIST : NPHV_DEBUG_MODE_WHITELIST;
    if (!Ioctl(IOCTL_NPHV_DEBUG_MODE, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[dbg] mode ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[dbg] mode = %s", black ? L"blacklist（除注册外全藏）" : L"whitelist");
}

static void GuiDoPhOnOff(bool on)
{
    NPHV_PROCESS_HIDE_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.Enable = on ? 1 : 0;
    if (!Ioctl(IOCTL_NPHV_PROCESS_HIDE, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[prochide] ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[prochide] %s", on ? L"enabled" : L"disabled");
}

static void GuiDoPhAddDel(bool add)
{
    wchar_t name[64] = {0};
    GetWindowTextW(Ctrl(IDC_PH_NAME), name, 64);
    if (!name[0]) { GuiLogF(L"[prochide] 请输入进程名（如 game.exe）"); return; }
    NPHV_PROCESS_HIDE_NAME_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    wcsncpy(req.Name, name, 63);
    ULONG code = add ? IOCTL_NPHV_PROCESS_HIDE_ADD : IOCTL_NPHV_PROCESS_HIDE_REMOVE;
    if (!Ioctl(code, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[prochide] ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[prochide] %s %s", add ? L"added" : L"removed", name);
}

static void GuiDoPhList()
{
    NPHV_PROCESS_HIDE_LIST_RESPONSE resp;
    memset(&resp, 0, sizeof(resp));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_PROCESS_HIDE_LIST, &resp, 0, sizeof(resp), &ret))
    {
        GuiLogF(L"[prochide] list ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[prochide] %s count=%lu", resp.Enabled ? L"enabled" : L"disabled",
            resp.Count);
    for (ULONG i = 0; i < resp.Count && i < 16; i++)
        GuiLogF(L"   [%lu] %s", i, resp.Names[i]);
    // 查看者豁免名单：名单内进程（自家调试器）枚举时不过滤
    NPHV_PROCESS_HIDE_LIST_RESPONSE wresp;
    memset(&wresp, 0, sizeof(wresp));
    if (Ioctl(IOCTL_NPHV_PROCESS_WATCH_LIST, &wresp, 0, sizeof(wresp), &ret))
    {
        GuiLogF(L"[prochide] 查看者 count=%lu（这些进程不受过滤）", wresp.Count);
        for (ULONG i = 0; i < wresp.Count && i < 16; i++)
            GuiLogF(L"   [W%lu] %s", i, wresp.Names[i]);
    }
}

static void GuiDoPhWatch(bool add)
{
    wchar_t name[64] = {0};
    GetWindowTextW(Ctrl(IDC_PH_NAME), name, 64);
    if (!name[0]) { GuiLogF(L"[prochide] 请输入查看者进程名（如 x64dbg.exe）"); return; }
    NPHV_PROCESS_HIDE_NAME_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    wcsncpy(req.Name, name, 63);
    ULONG code = add ? IOCTL_NPHV_PROCESS_WATCH_ADD : IOCTL_NPHV_PROCESS_WATCH_REMOVE;
    if (!Ioctl(code, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[prochide] watch ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[prochide] %s查看者 %s%s", add ? L"添加" : L"移除", name,
            add ? L"（其枚举不再被过滤）" : L"");
}

static void GuiDoHookInstall()
{
    NPHV_INSTALL_HOOK_REQUEST req;
    NPHV_INSTALL_HOOK_RESPONSE resp;
    memset(&req, 0, sizeof(req)); memset(&resp, 0, sizeof(resp));
    req.Version = NPHV_PROTOCOL_VERSION;
    wchar_t tgt[128] = {0}, retv[32] = {0};
    GetWindowTextW(Ctrl(IDC_HK_TARGET), tgt, 128);
    GetWindowTextW(Ctrl(IDC_HK_RET), retv, 32);
    if (!tgt[0]) { GuiLogF(L"[hook] 请输入目标函数名/地址"); return; }
    unsigned long long av;
    if (wcslen(tgt) >= 8 && ParseHex64(tgt, av))
        req.TargetAddress = av;
    else
        W2A(tgt, req.TargetName, sizeof(req.TargetName));
    int sel = (int)SendMessageW(Ctrl(IDC_HK_ACTION),
                                CB_GETCURSEL, 0, 0);
    switch (sel < 0 ? 0 : sel)
    {
    case 1:  req.Action = NpHookActionReturnValue;
             ParseHex64(retv, req.ReturnValue); break;
    case 2:  req.Action = NpHookActionPassThrough; break;
    default: req.Action = NpHookActionLogOnly; break;
    }
    UCHAR buf[sizeof(req) + sizeof(resp)];
    memcpy(buf, &req, sizeof(req));
    ULONG ret = 0;
    if (!Ioctl(IOCTL_NPHV_INSTALL_HOOK, buf, sizeof(buf), sizeof(buf), &ret))
    {
        GuiLogF(L"[hook] ioctl failed (err=%lu)", GetLastError()); return;
    }
    memcpy(&resp, buf + sizeof(req), sizeof(resp));
    if (resp.Status != 0)
    {
        GuiLogF(L"[hook] install failed: %s (%08X)",
                NtStatusNameW(resp.Status), resp.Status);
        return;
    }
    GuiLogF(L"[hook] installed HookId=%u （记下它用于 unhook）", resp.HookId);
}

static void GuiDoHookUninstall()
{
    wchar_t idt[16] = {0};
    GetWindowTextW(Ctrl(IDC_HK_ID), idt, 16);
    uint32_t id = (uint32_t)wcstoul(idt, nullptr, 10);
    if (!id) { GuiLogF(L"[hook] 请输入 HookId"); return; }
    NPHV_UNINSTALL_HOOK_REQUEST req;
    memset(&req, 0, sizeof(req));
    req.Version = NPHV_PROTOCOL_VERSION;
    req.HookId = id;
    if (!Ioctl(IOCTL_NPHV_UNINSTALL_HOOK, &req, sizeof(req), 0, nullptr))
    {
        GuiLogF(L"[hook] uninstall ioctl failed (err=%lu)", GetLastError()); return;
    }
    GuiLogF(L"[hook] uninstalled id=%u", id);
}

static void GuiDoHookUninstallAll()
{
    if (!Ioctl(IOCTL_NPHV_UNINSTALL_ALL, nullptr, 0, 0, nullptr))
    {
        GuiLogF(L"[hook] uninstall-all ioctl failed (err=%lu)", GetLastError());
        return;
    }
GuiLogF(L"[hook] all hooks uninstalled (retired)");
}

static void GuiDoDrvInstall(){
    if(!DrvIsAdmin()){ GuiLogF(L"[drv] 未以管理员运行，正在提权..."); DrvRequestAdmin(L"/drv_install"); return; }
    if(!SecGateGui()){ GuiLogF(L"[drv] 已取消：VBS/HVCI/Defender 实时防护未关闭"); return; }
    srand((unsigned)GetTickCount());
    std::wstring npPath; if(!DrvExtractNpHv(npPath)){ GuiLogF(L"[drv] 内嵌 NpHv 释放失败"); return; }
    std::wstring hwPath; if(!DrvExtractHw(hwPath)){ GuiLogF(L"[drv] 内嵌 HwRw 释放失败"); DeleteFileW(npPath.c_str()); return; }
    std::wstring svc = L"NpHv_" + std::to_wstring(GetTickCount()%100000) + L"_" + std::to_wstring(rand()%1000);
    std::wstring hwSvc = L"HwRw" + std::to_wstring(rand()%100000);
    GuiLogF(L"[drv] BYOVD 安装 -> 服务 %s (NpHv %s)", svc.c_str(), npPath.c_str());
    // 1) 加载漏洞驱动（随机文件名+随机服务名）
    if(!DrvScmLoad(hwPath, hwSvc)){
        DWORD err=GetLastError();
        GuiLogF(L"[drv] HwRwDrv 加载失败 NTSTATUS 0x%08X (err=%lu) 可能被杀软拦截", (unsigned)err, (unsigned long)err);
        DeleteFileW(npPath.c_str()); DeleteFileW(hwPath.c_str()); return;
    }
    GuiLogF(L"[drv] HwRwDrv 已加载 %s，正在 CI 补丁 (SeCiCallbacks -> ZwFlushInstructionCache)...", hwSvc.c_str());
    // 2) CI 补丁：物理内存改 SeCiCallbacks -> ZwFlushInstructionCache
    bool patched = CiPatchSeCiCallbacks();
    if(!patched) GuiLogF(L"[drv] CI 补丁失败，仍尝试加载 NpHv (0xC0000428 预期)");
    else GuiLogF(L"[drv] CI 补丁成功");
    // 3) 加载目标驱动（此时 CI 已绕过，0xC0000428 应消失）
    bool ok = DrvScmLoad(npPath, svc);
    DWORD errOk = GetLastError();
    // 4) 恢复 CI 并清理 HwRwDrv
    CiRestoreSeCiCallbacks();
    DrvScmUnload(hwSvc); DeleteFileW(hwPath.c_str());
    // 5) 目标驱动文件可删（已入内核）
    // 保留 npPath 供卸载时删除注册表指向的文件？已 DeleteFile 不影响已加载驱动
    if(ok){
        GuiLogF(L"[drv] BYOVD 安装成功 服务=%s", svc.c_str());
        HKEY h; RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\NpHvCtl",0,NULL,0,KEY_WRITE,NULL,&h,NULL);
        RegSetValueExW(h,L"LastService",0,REG_SZ,(BYTE*)svc.c_str(),(DWORD)((svc.size()+1)*2)); RegCloseKey(h);
        DeleteFileW(npPath.c_str());
        if(g_hDev!=INVALID_HANDLE_VALUE){ CloseHandle(g_hDev); g_hDev=INVALID_HANDLE_VALUE; }
        OpenDevice();
        GuiDoRefreshStatus();
    } else {
        GuiLogF(L"[drv] NpHv 加载失败 NTSTATUS 0x%08X err=%lu (若仍是0xC0000428说明CI补丁未生效)", (unsigned)errOk, (unsigned long)errOk);
        DeleteFileW(npPath.c_str());
    }
}
static void GuiDoDrvUninstall(){
    if(!DrvIsAdmin()){ GuiLogF(L"[drv] 未以管理员运行，正在提权..."); DrvRequestAdmin(L"/drv_uninstall"); return; }
    wchar_t svc[128]={0}; DWORD cb=sizeof(svc); HKEY h; if(RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\NpHvCtl",0,KEY_READ,&h)==ERROR_SUCCESS){ RegQueryValueExW(h,L"LastService",NULL,NULL,(BYTE*)svc,&cb); RegCloseKey(h); }
    std::wstring targets[] = { svc[0]?svc:L"NpHv", L"NpHv", L"drv0", L"drv1" };
    bool any=false;
    for(auto &t: targets){ if(t.empty()) continue; if(DrvScmUnload(t)){ GuiLogF(L"[drv] 已卸载 %s", t.c_str()); any=true; } }
    if(true){ GuiLogF(L"[drv] 已尝试卸载 Hypervisor"); } // placeholder
    if(!any) GuiLogF(L"[drv] 未找到已安装的驱动服务");
    GuiDoRefreshStatus();
}

// ---- 面板构建 ----

static void BuildPanels()
{
    // 0 状态
    g_hCtlParent = g_Panel[0];
    MkCtl(0, L"BUTTON", L"刷新状态", WS_CHILD | WS_VISIBLE |
          BS_PUSHBUTTON, 12, 14, 130, 32, IDC_ST_REFRESH);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_MULTILINE |
          ES_READONLY | WS_VSCROLL, 12, 54, 918, 350, IDC_ST_TEXT);

    // 1 断点
    g_hCtlParent = g_Panel[1];
    MkCtl(0, L"STATIC", L"目标（函数名 或 16进制地址）：", WS_CHILD | WS_VISIBLE,
          12, 16, 220, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"NtQuerySystemInformation",
          WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 240, 13, 300, 26, IDC_BP_TARGET);
    MkCtl(0, L"BUTTON", L"HALT", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
          556, 15, 66, 22, IDC_BP_HALT);
    MkCtl(0, L"BUTTON", L"ONESHOT", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
          628, 15, 84, 22, IDC_BP_ONESHOT);
    MkCtl(0, L"BUTTON", L"安装断点", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          730, 11, 110, 32, IDC_BP_INSTALL);
    MkCtl(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE |
          LVS_REPORT | LVS_SHOWSELALWAYS, 12, 52, 918, 300, IDC_BP_LIST);
    MkCtl(0, L"BUTTON", L"刷新列表", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          12, 364, 110, 32, IDC_BP_REFRESH);
    MkCtl(0, L"BUTTON", L"删除选中", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          132, 364, 110, 32, IDC_BP_DELETE);
    MkCtl(0, L"BUTTON", L"继续选中", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          252, 364, 110, 32, IDC_BP_CONTSEL);
    MkCtl(0, L"BUTTON", L"全部继续(bpcont all)", WS_CHILD | WS_VISIBLE |
          BS_PUSHBUTTON, 372, 364, 170, 32, IDC_BP_CONTALL);

    // 2 监视
    g_hCtlParent = g_Panel[2];
    MkCtl(0, L"STATIC", L"目标：", WS_CHILD | WS_VISIBLE, 12, 16, 60, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 80, 13, 320, 26, IDC_MON_TARGET);
    MkCtl(0, L"BUTTON", L"读(R)", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
          420, 15, 60, 22, IDC_MON_R);
    MkCtl(0, L"BUTTON", L"写(W)", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
          486, 15, 60, 22, IDC_MON_W);
    MkCtl(0, L"BUTTON", L"安装监视", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          600, 11, 110, 32, IDC_MON_INSTALL);
    MkCtl(0, L"STATIC", L"监视 ID：", WS_CHILD | WS_VISIBLE, 12, 62, 70, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 90, 59, 100, 26, IDC_MON_ID);
    MkCtl(0, L"BUTTON", L"卸载该监视", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          200, 57, 110, 32, IDC_MON_DELETE);
    MkCtl(0, L"STATIC",
          L"提示：命中记录经 bplist 类查询不可用，监视 ID 请自行记录；"
          L"读监视会连取指一起拦（AMD 无 execute-only）。",
          WS_CHILD | WS_VISIBLE, 12, 96, 918, 20, 0);

    // 3 内存
    g_hCtlParent = g_Panel[3];
    MkCtl(0, L"STATIC", L"PID：", WS_CHILD | WS_VISIBLE, 12, 16, 46, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 62, 13, 90, 26, IDC_MEM_PID);
    MkCtl(0, L"STATIC", L"地址(hex)：", WS_CHILD | WS_VISIBLE, 166, 16, 76, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 246, 13, 190, 26, IDC_MEM_ADDR);
    MkCtl(0, L"STATIC", L"长度(hex)：", WS_CHILD | WS_VISIBLE, 450, 16, 76, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"40", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 530, 13, 90, 26, IDC_MEM_LEN);
    MkCtl(0, L"BUTTON", L"无痕读取", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          650, 11, 110, 32, IDC_MEM_READ);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_MULTILINE |
          ES_READONLY | WS_VSCROLL, 12, 52, 918, 352, IDC_MEM_DUMP);

    // 4 调试隐藏
    g_hCtlParent = g_Panel[4];
    MkCtl(0, L"BUTTON", L"调试隐藏 开（含窗口改名）", WS_CHILD | WS_VISIBLE |
          BS_PUSHBUTTON, 12, 14, 230, 30, IDC_DBG_ON);
    MkCtl(0, L"BUTTON", L"调试隐藏 关", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          252, 14, 150, 30, IDC_DBG_OFF);
    MkCtl(0, L"BUTTON", L"drprobe 开", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          12, 56, 110, 32, IDC_DR_ON);
    MkCtl(0, L"BUTTON", L"drprobe 关", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          132, 56, 110, 32, IDC_DR_OFF);
    MkCtl(0, L"BUTTON", L"查询 drstate", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          252, 56, 130, 32, IDC_DRSTATE_BTN);
    MkCtl(0, L"STATIC", L"目标 PID：", WS_CHILD | WS_VISIBLE, 12, 106, 76, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 92, 103, 100, 26, IDC_DBG_PID);
    MkCtl(0, L"BUTTON", L"注册保护", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          202, 101, 100, 32, IDC_DBG_PROTECT);
    MkCtl(0, L"BUTTON", L"注销", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          312, 101, 80, 32, IDC_DBG_UNPROTECT);
    MkCtl(0, L"BUTTON", L"白名单模式", WS_CHILD | WS_VISIBLE |
          BS_AUTORADIOBUTTON, 12, 146, 110, 22, IDC_MODE_WHITE);
    MkCtl(0, L"BUTTON", L"黑名单模式", WS_CHILD | WS_VISIBLE |
          BS_AUTORADIOBUTTON, 132, 146, 110, 22, IDC_MODE_BLACK);
    MkCtl(0, L"BUTTON", L"应用模式", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          252, 142, 110, 32, IDC_MODE_APPLY);
    CheckRadioButton(g_Panel[4], IDC_MODE_WHITE, IDC_MODE_BLACK, IDC_MODE_WHITE);

    // 5 进程隐藏
    g_hCtlParent = g_Panel[5];
    MkCtl(0, L"BUTTON", L"启用 prochide", WS_CHILD | WS_VISIBLE |
          BS_PUSHBUTTON, 12, 14, 140, 32, IDC_PH_ON);
    MkCtl(0, L"BUTTON", L"停用", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          162, 14, 90, 32, IDC_PH_OFF);
    MkCtl(0, L"STATIC", L"进程名：", WS_CHILD | WS_VISIBLE, 12, 58, 64, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"game.exe", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 82, 55, 240, 26, IDC_PH_NAME);
    MkCtl(0, L"BUTTON", L"添加", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          332, 53, 80, 32, IDC_PH_ADD);
    MkCtl(0, L"BUTTON", L"删除", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          420, 53, 80, 32, IDC_PH_DEL);
    MkCtl(0, L"BUTTON", L"清空名单", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          510, 53, 100, 32, IDC_PH_CLEAR);
    MkCtl(0, L"BUTTON", L"查看名单", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          12, 96, 110, 32, IDC_PH_LIST);
    MkCtl(0, L"BUTTON", L"加查看者", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          132, 96, 100, 32, IDC_PH_WATCH_ADD);
    MkCtl(0, L"BUTTON", L"删查看者", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          240, 96, 100, 32, IDC_PH_WATCH_DEL);
    MkCtl(0, L"STATIC", L"查看者＝自己的调试器，其进程枚举不被过滤",
          WS_CHILD | WS_VISIBLE, 352, 101, 300, 20, 0);

    // 6 Hook
    g_hCtlParent = g_Panel[6];
    MkCtl(0, L"STATIC", L"目标：", WS_CHILD | WS_VISIBLE, 12, 16, 52, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 70, 13, 280, 26, IDC_HK_TARGET);
    MkCtl(0, L"STATIC", L"动作：", WS_CHILD | WS_VISIBLE, 364, 16, 50, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE |
          CBS_DROPDOWNLIST, 420, 13, 140, 200, IDC_HK_ACTION);
    MkCtl(0, L"STATIC", L"返回值(hex)：", WS_CHILD | WS_VISIBLE, 574, 16, 88, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"0", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 666, 13, 120, 26, IDC_HK_RET);
    MkCtl(0, L"BUTTON", L"安装 Hook", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          800, 11, 110, 32, IDC_HK_INSTALL);
    MkCtl(0, L"STATIC", L"HookId：", WS_CHILD | WS_VISIBLE, 12, 58, 60, 20, 0);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE |
          ES_AUTOHSCROLL, 78, 55, 100, 26, IDC_HK_ID);
    MkCtl(0, L"BUTTON", L"卸载该 Hook", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          188, 53, 110, 32, IDC_HK_UNINSTALL);
    MkCtl(0, L"BUTTON", L"卸载全部", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          308, 53, 100, 32, IDC_HK_UNALL);

    // 7 驱动
    g_hCtlParent = g_Panel[7];
    MkCtl(0, L"STATIC", L"驱动安装/卸载（集成 PhysDrvLoader，随机文件名，自动提权）：", WS_CHILD|WS_VISIBLE, 12,16,600,20,0);
    MkCtl(0, L"BUTTON", L"安装驱动", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 12,44,150,36, IDC_DRV_INSTALL);
    MkCtl(0, L"BUTTON", L"卸载驱动", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 172,44,150,36, IDC_DRV_UNINSTALL);
    MkCtl(0, L"BUTTON", L"刷新状态", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 332,44,110,36, IDC_DRV_STATUS);
    MkCtl(WS_EX_CLIENTEDGE, L"EDIT", L"提示：安装前自动请求管理员权限；HwRwDrv.sys 随机释放到%TEMP%，服务名随机；先尝试 SCM 直接加载，失败再走 BYOVD。", WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_READONLY, 12,96,918,60, IDC_DRV_LOG);

}

static void SwitchPanel(int idx)
{
    for (int i = 0; i < GUI_PANELS; i++)
        ShowWindow(g_Panel[i], (i == idx) ? SW_SHOW : SW_HIDE);
    if (idx == 0) GuiDoRefreshStatus();
}

// 页签容器窗口过程：转发子控件消息给主窗口统一处理（STATIC 类会吞掉
// WM_COMMAND/WM_NOTIFY，导致按钮点击无响应——必须自定义容器类）。
static LRESULT CALLBACK PanelProc(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg)
    {
    case WM_COMMAND:
    case WM_NOTIFY:
    case WM_DRAWITEM:
        return SendMessageW(g_hMain, msg, w, l);
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
        return SendMessageW(g_hMain, msg, w, l);
    case WM_ERASEBKGND:
    {
        HDC dc = (HDC)w;
        RECT rc;
        GetClientRect(h, &rc);
        FillRect(dc, &rc, g_hBrBk);
        return 1;
    }
    default:
        return DefWindowProcW(h, msg, w, l);
    }
}

static LRESULT CALLBACK GuiWndProc(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg)
    {
    case WM_NOTIFY:
    {
        NMHDR* nm = (NMHDR*)l;
        if (nm->idFrom == IDC_TAB && nm->code == TCN_SELCHANGE)
            SwitchPanel((int)SendMessageW(g_hTab, TCM_GETCURSEL, 0, 0));
        break;
    }
    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)w, TRANSPARENT);
        return (LRESULT)(g_hBrBk ? g_hBrBk : GetSysColorBrush(COLOR_BTNFACE));
    case WM_COMMAND:
        GuiOnCommand(LOWORD(w), HIWORD(w));
        break;
    case WM_TIMER:
        if ((int)SendMessageW(g_hTab, TCM_GETCURSEL, 0, 0) == 0)
            GuiDoRefreshStatus();
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(h, msg, w, l);
    }
    return 0;
}

static BOOL CALLBACK ApplyFontProc(HWND h, LPARAM l)
{
    SendMessageW(h, WM_SETFONT, (WPARAM)l, TRUE);
    return TRUE;
}

static void BuildTab(const wchar_t* title, int idx)
{
    TCITEMW ti;
    memset(&ti, 0, sizeof(ti));
    ti.mask = TCIF_TEXT; ti.pszText = (LPWSTR)title;
    SendMessageW(g_hTab, TCM_INSERTITEMW, idx, (LPARAM)&ti);
}

static int RunGui()
{
    CtlTrace("RunGui enter");
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSW wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = GuiWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NpHvCtlGui";
    RegisterClassW(&wc);
    CtlTrace("RunGui after RegisterClassW");

    WNDCLASSW wpc;
    memset(&wpc, 0, sizeof(wpc));
    wpc.lpfnWndProc = PanelProc;
    wpc.hInstance = GetModuleHandleW(nullptr);
    wpc.hCursor = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wpc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wpc.lpszClassName = L"NpHvPanel";
    RegisterClassW(&wpc);

    g_hFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    g_hFontMono = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              FIXED_PITCH | FF_MODERN, L"Consolas");
    g_hBrBk = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));

    g_hMain = CreateWindowExW(0, L"NpHvCtlGui",
                              L"NpHv 控制台 — AMD NPT 无痕断点框架",
                              WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
                              CW_USEDEFAULT, CW_USEDEFAULT, 996, 738,
                              nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    CtlTrace(g_hMain ? "RunGui after CreateWindowExW ok" : "RunGui CreateWindowExW FAILED");
    if (!g_hMain) return 1;

    RECT rcCli; GetClientRect(g_hMain, &rcCli);
    int cw = rcCli.right - rcCli.left;    // ≈980
    int ch = rcCli.bottom - rcCli.top;    // ≈700

    g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
                             WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_TABS,
                             8, 8, cw - 16, 472,
                             g_hMain, (HMENU)(intptr_t)IDC_TAB,
                             GetModuleHandleW(nullptr), nullptr);
    BuildTab(L"状态", 0);
    BuildTab(L"断点", 1);
    BuildTab(L"监视", 2);
    BuildTab(L"内存", 3);
    BuildTab(L"调试隐藏", 4);
    BuildTab(L"进程隐藏", 5);
    BuildTab(L"Hook", 6);
    BuildTab(L"驱动", 7);

    // 面板容器：自定义类（转发子控件消息），直接铺在主窗口上
    const wchar_t* panelCls = L"NpHvPanel";
    for (int i = 0; i < GUI_PANELS; i++)
    {
        g_Panel[i] = CreateWindowExW(0, panelCls, L"",
                                     WS_CHILD | WS_CLIPSIBLINGS |
                                     (i == 0 ? WS_VISIBLE : 0),
                                     20, 44, cw - 42, 424,
                                     g_hMain, nullptr,
                                     GetModuleHandleW(nullptr), nullptr);
    }
    // z 序修正：本机上 CreateWindowExW 把新子窗口插到兄弟 z 序底部，
    // 最先创建的页签控件反而留在最顶层，其不透明显示区把面板连同里面
    // 的控件全部盖住（现象：所有页签内容一片空白）。显式把面板抬到
    // 兄弟最上层（面板顶边 y=44 在页签头下方，不会遮挡页签的点击）。
    for (int i = 0; i < GUI_PANELS; i++)
    {
        if (g_Panel[i])
            SetWindowPos(g_Panel[i], HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    // 日志区折叠按钮：始终可见，固定在日志区上沿；点击切换 g_hLog 显隐。
    // 折叠后下方留白，不重排 Tab（避免布局抖动；后续若要自适应可改 WM_SIZE）。
    //
    // ---- 日志区 ----
    g_hLogToggle = CreateWindowExW(0, L"BUTTON", L"\x25B2 \x65E5\x5FD7\x533A \x6536\x8D77",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   cw - 96, 484, 88, 18, g_hMain,
                                   (HMENU)(intptr_t)IDC_LOG_TOGGLE,
                                   GetModuleHandleW(nullptr), nullptr);
    g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
                             WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                             ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                             8, 490, cw - 16, ch - 498,
                             g_hMain, (HMENU)(intptr_t)IDC_LOG,
                             GetModuleHandleW(nullptr), nullptr);

    BuildPanels();

    // 断点列表列
    HWND lv = Ctrl(IDC_BP_LIST);
    LvAddCol(lv, 0, 46, L"ID");
    LvAddCol(lv, 1, 150, L"地址");
    LvAddCol(lv, 2, 110, L"模式");
    LvAddCol(lv, 3, 80, L"命中");
    LvAddCol(lv, 4, 64, L"状态");
    LvAddCol(lv, 5, 170, L"最近 RIP");
    LvAddCol(lv, 6, 60, L"CPU");
    SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                 LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // 下拉框选项
    HWND cb = Ctrl(IDC_HK_ACTION);
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"log（记录放行）");
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"ret（拦截返回值）");
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"pass（直通）");
    SendMessageW(cb, CB_SETCURSEL, 0, 0);

    EnumChildWindows(g_hMain, ApplyFontProc, (LPARAM)g_hFont);
    SendMessageW(Ctrl(IDC_MEM_DUMP), WM_SETFONT,
                 (WPARAM)g_hFontMono, TRUE);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);

    // 居中
    RECT wr, wa;
    GetWindowRect(g_hMain, &wr);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    SetWindowPos(g_hMain, nullptr,
                 (wa.left + wa.right - (wr.right - wr.left)) / 2,
                 (wa.top + wa.bottom - (wr.bottom - wr.top)) / 2,
                 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // 设备连接检查
    if (!OpenDevice())
        GuiAppendLog(L"[!] 无法打开 \\\\.\\NpHv —— 请先 sc start NpHv\r\n");
    else
        GuiAppendLog(L"[ok] 设备已连接。左侧页签选择功能；操作结果输出在此日志区。\r\n");
    GuiDoRefreshStatus();

    SetTimer(g_hMain, 1, 2000, nullptr);
    ShowWindow(g_hMain, SW_SHOWNORMAL);
    UpdateWindow(g_hMain);
    CtlTrace("RunGui after ShowWindow");

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        if ((g_hTab && IsDialogMessage(g_hMain, &msg)))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    KillTimer(g_hMain, 1);
    return 0;
}

// GUI 按钮命令分发（挂在主窗口过程里需要访问；此处通过 WM_COMMAND 转发）
static void GuiOnCommand(int id, int code)
{
    switch (id)
    {
    case IDC_ST_REFRESH:   GuiDoRefreshStatus(); break;
    case IDC_BP_INSTALL:   GuiDoBpInstall(); break;
    case IDC_BP_REFRESH:   GuiDoBpRefresh(); break;
    case IDC_BP_DELETE:    GuiDoBpDelete(); break;
    case IDC_BP_CONTSEL:
    {
        HWND lv = Ctrl(IDC_BP_LIST);
        int sel = LvSel(lv);
        wchar_t idt[16] = L"0";
        if (sel >= 0) LvText(lv, sel, 0, idt, 16);
        GuiDoBpCont((unsigned)wcstoul(idt, nullptr, 10));
        break;
    }
    case IDC_BP_CONTALL:   GuiDoBpCont(0); break;
    case IDC_MON_INSTALL:  GuiDoMonInstall(); break;
    case IDC_MON_DELETE:   GuiDoMonDelete(); break;
    case IDC_MEM_READ:     GuiDoMemRead(); break;
    case IDC_DBG_ON:       GuiDoDbgHide(TRUE); break;
    case IDC_DBG_OFF:      GuiDoDbgHide(FALSE); break;
    case IDC_DR_ON:        GuiDoDrProbe(true); break;
    case IDC_DR_OFF:       GuiDoDrProbe(false); break;
    case IDC_DRSTATE_BTN:  GuiDoDrState(); break;
    case IDC_DBG_PROTECT:  GuiDoProtect(TRUE); break;
    case IDC_DBG_UNPROTECT:GuiDoProtect(FALSE); break;
    case IDC_MODE_APPLY:
        GuiDoMode(Chk(IDC_MODE_BLACK));
        break;
    case IDC_PH_ON:        GuiDoPhOnOff(true); break;
    case IDC_PH_OFF:       GuiDoPhOnOff(false); break;
    case IDC_PH_ADD:       GuiDoPhAddDel(true); break;
    case IDC_PH_DEL:       GuiDoPhAddDel(false); break;
    case IDC_PH_CLEAR:
        if (Ioctl(IOCTL_NPHV_PROCESS_HIDE_CLEAR, nullptr, 0, 0, nullptr))
            GuiLogF(L"[prochide] cleared");
        else
            GuiLogF(L"[prochide] clear failed (err=%lu)", GetLastError());
        break;
    case IDC_PH_LIST:      GuiDoPhList(); break;
    case IDC_PH_WATCH_ADD: GuiDoPhWatch(true); break;
    case IDC_PH_WATCH_DEL: GuiDoPhWatch(false); break;
    case IDC_HK_INSTALL:   GuiDoHookInstall(); break;
    case IDC_HK_UNINSTALL: GuiDoHookUninstall(); break;
    case IDC_HK_UNALL:     GuiDoHookUninstallAll(); break;
    case IDC_DRV_INSTALL:  GuiDoDrvInstall(); break;
    case IDC_DRV_UNINSTALL: GuiDoDrvUninstall(); break;
    case IDC_DRV_STATUS:   GuiDoRefreshStatus(); break;
    case IDC_LOG_TOGGLE:
        if (g_hLog)
        {
            BOOL vis = IsWindowVisible(g_hLog);
            ShowWindow(g_hLog, vis ? SW_HIDE : SW_SHOWNORMAL);
            SetWindowTextW(g_hLogToggle,
                           vis ? L"\x25BC \x65E5\x5FD7\x533A \x5C55\x5F00"
                               : L"\x25B2 \x65E5\x5FD7\x533A \x6536\x8D77");
        }
        break;
    default: break;
    }
    (void)code;
}

static int RunCliMain(int argc, char* argv[]);   // fwd：命令行模式

// CLI 模式控制台绑定：本 exe 以 GUI 子系统（-mwindows）编译，启动时系统
// 不再分配控制台（GUI 双击无黑框）。带参数进入 CLI 时按场景恢复输出：
//   1) stdout 已被重定向（> file / 管道）：标准句柄有效，CRT 已接好，直接用；
//   2) 交互式（从 cmd/PowerShell 启动）：AttachConsole 附着父控制台并重开
//      stdin/stdout/stderr，输出与原控制台版一致；
//   3) 附着失败（无父控制台）：AllocConsole 兜底。
static void SetupCliConsole()
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out != nullptr && out != INVALID_HANDLE_VALUE &&
        GetFileType(out) != FILE_TYPE_UNKNOWN)
        return;                                  // 场景 1：重定向，保持原样

    if (!AttachConsole(ATTACH_PARENT_PROCESS))   // 场景 2
        AllocConsole();                          // 场景 3：兜底
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
}

int main(int argc, char* argv[])
{
    CtlTrace("main enter");
    if (argc >= 2 && strcmp(argv[1], "/drv_install")==0){
        if(!DrvIsAdmin()){ DrvRequestAdmin(L"/drv_install"); return 0; }
        if(!SecGateCli()){ printf("[sec] install aborted\n"); return 0; }
        // elevation path will re-enter here as admin, do install then exit
        srand((unsigned)GetTickCount());
        std::wstring npPath; DrvExtractNpHv(npPath);
        std::wstring hwPath; bool hasHw=DrvExtractHw(hwPath);
        std::wstring svc = L"NpHv_" + std::to_wstring(GetTickCount()%100000)+L"_"+std::to_wstring(rand()%1000);
        if(!npPath.empty() && DrvScmLoad(npPath, svc)){
            if(g_hDev!=INVALID_HANDLE_VALUE){ CloseHandle(g_hDev); g_hDev=INVALID_HANDLE_VALUE; } OpenDevice();
            HKEY h; RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\NpHvCtl",0,NULL,0,KEY_WRITE,NULL,&h,NULL);
            RegSetValueExW(h,L"LastService",0,REG_SZ,(BYTE*)svc.c_str(),(DWORD)((svc.size()+1)*2)); RegCloseKey(h);
            DeleteFileW(npPath.c_str()); if(hasHw) DeleteFileW(hwPath.c_str());
        }
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "/drv_uninstall")==0){
        if(!DrvIsAdmin()){ DrvRequestAdmin(L"/drv_uninstall"); return 0; }
        wchar_t svc[128]={0}; DWORD cb=sizeof(svc); HKEY h; if(RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\NpHvCtl",0,KEY_READ,&h)==ERROR_SUCCESS){ RegQueryValueExW(h,L"LastService",NULL,NULL,(BYTE*)svc,&cb); RegCloseKey(h); }
        if(svc[0]) DrvScmUnload(svc);
        DrvScmUnload(L"NpHv");
        return 0;
    }
    if (argc >= 2)
    {
        SetupCliConsole();                  // CLI：恢复控制台输出（脚本兼容）
        return RunCliMain(argc, argv);
    }

    return RunGui();                        // GUI：GUI 子系统，本就无黑框
}

// ---- CLI 模式：保留全部原始命令（带参数时进入，脚本兼容） ----
static int RunCliMain(int argc, char* argv[])
{
    CtlTrace("RunCliMain enter");
    printf(NpDec(31), NPHV_PROTOCOL_VERSION);

    if (!OpenDevice())
    {
        printf(NpDec(32), GetLastError());
        printf(NpDec(33));
        return 1;
    }

    const char* cmd = (argc > 1) ? argv[1] : "demo";
    int rc = 0;

    if (strcmp(cmd, "status") == 0)
    {
        rc = CmdStatus();
    }
    else if (strcmp(cmd, "hook") == 0)
    {
        rc = CmdHook(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "unhook") == 0 && argc >= 3)
    {
        rc = CmdUnhook(static_cast<ULONG>(strtoul(argv[2], nullptr, 0)));
    }
    else if (strcmp(cmd, "unhookall") == 0)
    {
        rc = CmdUnhookAll();
    }
    else if (strcmp(cmd, "unload") == 0)
    {
        rc = CmdUnload();
    }
    else if (strcmp(cmd, "bp") == 0)
    {
        rc = CmdBp(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "bpdel") == 0 && argc >= 3)
    {
        rc = CmdBpDel(static_cast<ULONG>(strtoul(argv[2], nullptr, 0)));
    }
    else if (strcmp(cmd, "bplist") == 0)
    {
        rc = CmdBpList();
    }
    else if (strcmp(cmd, "bpcont") == 0 && argc >= 3)
    {
        rc = CmdBpCont(argv[2]);
    }
    else if (strcmp(cmd, "mon") == 0)
    {
        rc = CmdMon(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "mondel") == 0 && argc >= 3)
    {
        rc = CmdMonDel(static_cast<ULONG>(strtoul(argv[2], nullptr, 0)));
    }
    else if (strcmp(cmd, "mem") == 0)
    {
        rc = CmdMem(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "drprobe") == 0 && argc >= 3)
    {
        rc = CmdDrProbe(argv[2]);
    }
    else if (strcmp(cmd, "drstate") == 0)
    {
        rc = CmdDrState();
    }
    else if (strcmp(cmd, "prochide") == 0)
    {
        rc = CmdProcHide(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "dbg") == 0)
    {
        rc = CmdDbg(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "syscheck") == 0)
    {
        rc = CmdSyscheck();
    }
    else if (strcmp(cmd, "demo") == 0)
    {
        rc = CmdDemo();
    }
    else
    {
        printf(NpDec(34), cmd);
        rc = 1;
    }

    CloseHandle(g_hDev);
    return rc;
}
