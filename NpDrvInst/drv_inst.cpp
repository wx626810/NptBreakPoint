#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "drv_inst.h"
#include "DrvMgr.h"
#include "CiPatch.h"
#include "SecCheck.h"
#include "Hypercall.h"

// ---------------- 传输层（移植 Win32 OpenDevice/Ioctl，hypercall优先） ----------------
static HANDLE g_trDev = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_trCs;
static bool g_trInit = false;
static void TrEnsureInit(){ if(!g_trInit){ InitializeCriticalSection(&g_trCs); g_trInit = true; } }

static BOOL TrOpenLocked(){
    if(g_trDev != INVALID_HANDLE_VALUE) return TRUE;
    wchar_t devName[64] = {0};
    if(HcGetDeviceName(devName, 64) && devName[0] && wcslen(devName) > 5){
        wchar_t* base = wcsrchr(devName, L'\\');
        base = base ? base + 1 : devName;
        char ansi[128] = {0};
        WideCharToMultiByte(CP_ACP,0,(std::wstring(L"\\\\.\\")+base).c_str(),-1,ansi,128,NULL,NULL);
        g_trDev = CreateFileA(ansi, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if(g_trDev != INVALID_HANDLE_VALUE) return TRUE;
    }
    DWORD bufChars = 32768;
    wchar_t* dosBuf = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, bufChars*sizeof(wchar_t));
    if(dosBuf){
        DWORD ret = QueryDosDeviceW(NULL, dosBuf, bufChars);
        if(ret && ret < bufChars){
            for(wchar_t* p = dosBuf; *p; ){
                size_t len = wcslen(p);
                if(len == 0) break;
                if(len >= 5 && wcsncmp(p, L"NpHv_", 5) == 0){
                    char ansi2[128] = {0};
                    WideCharToMultiByte(CP_ACP,0,(std::wstring(L"\\\\.\\")+p).c_str(),-1,ansi2,128,NULL,NULL);
                    g_trDev = CreateFileA(ansi2, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if(g_trDev != INVALID_HANDLE_VALUE){ HeapFree(GetProcessHeap(),0,dosBuf); return TRUE; }
                }
                p += len + 1;
            }
        }
        HeapFree(GetProcessHeap(),0,dosBuf);
    }
    g_trDev = CreateFileA("\\\\.\\NpHv", GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return (g_trDev != INVALID_HANDLE_VALUE);
}

extern "C" {
NPT_API uint32_t NpT_Open(void){ TrEnsureInit(); EnterCriticalSection(&g_trCs); BOOL ok = TrOpenLocked(); DWORD e = ok?0:GetLastError(); LeaveCriticalSection(&g_trCs); return e; }
NPT_API void NpT_Close(void){ TrEnsureInit(); EnterCriticalSection(&g_trCs); if(g_trDev!=INVALID_HANDLE_VALUE){ CloseHandle(g_trDev); g_trDev=INVALID_HANDLE_VALUE; } LeaveCriticalSection(&g_trCs); }
NPT_API uint32_t NpT_Ioctl(uint32_t code, uint8_t* buf, uint32_t len, uint32_t* outRet){
    if(!buf || !len) return ERROR_INVALID_PARAMETER;
    TrEnsureInit(); EnterCriticalSection(&g_trCs);
    if(!TrOpenLocked()){ DWORD e=GetLastError(); LeaveCriticalSection(&g_trCs); return e; }
    DWORD br = 0;
    BOOL ok = DeviceIoControl(g_trDev, code, buf, len, buf, len, &br, nullptr);
    if(!ok && GetLastError()==ERROR_INVALID_HANDLE){
        CloseHandle(g_trDev); g_trDev=INVALID_HANDLE_VALUE;
        if(TrOpenLocked()){ ok = DeviceIoControl(g_trDev, code, buf, len, buf, len, &br, nullptr); }
    }
    DWORD e = ok?0:GetLastError();
    if(outRet) *outRet = br;
    LeaveCriticalSection(&g_trCs);
    return e;
}
NPT_API uint32_t NpT_HcStatus(uint8_t out24[24]){ return HcQueryStatus(out24, 24) ? 1 : 0; }
NPT_API uint32_t NpT_HcDbgHide(uint32_t en){ return HcDbgHide(en?true:false) ? 1 : 0; }
NPT_API uint32_t NpT_HcProtect(uint32_t pid, uint32_t p){ return HcDbgProtect(pid, p?true:false) ? 1 : 0; }
NPT_API uint32_t NpT_HcMode(uint32_t mode){ return HcDbgMode(mode) ? 1 : 0; }
NPT_API uint32_t NpT_HcLicenseSet(const char* token){ return HcLicenseSet(token) ? 1 : 0; }
NPT_API uint32_t NpT_IsAdmin(void){ return DrvIsAdmin() ? 1 : 0; }
NPT_API uint32_t NpT_SecGate(wchar_t* msgOut, uint32_t msgCap){
    SecFindings f = SecQueryAll();
    if(!f.any()) return 0;
    if(msgOut && msgCap) SecBuildMessage(f, msgOut, msgCap);
    return 1;
}
} // extern C

// ---------------- 窗口联动（移植 Win32 DoWndHide/DoWndRestore，全量） ----------------
static const char* const kDbgImageNames[] = { "x64dbg.exe", "x32dbg.exe" };
static const char* const kWndRegKey = "Software\\NpHv\\WndHide";
static char WndLowerCh(char c){ return (c>='A'&&c<='Z') ? (char)(c+32) : c; }
static bool WndIsDebuggerProcess(HWND hWnd){
    DWORD pid = 0; GetWindowThreadProcessId(hWnd, &pid);
    if(!pid) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if(!h) return false;
    char path[MAX_PATH*2] = {0}; DWORD sz = sizeof(path);
    BOOL ok = QueryFullProcessImageNameA(h, 0, path, &sz);
    CloseHandle(h);
    if(!ok) return false;
    const char* name = path;
    for(const char* q = path; *q; ++q) if(*q=='\\'||*q=='/') name = q+1;
    for(const char* img : kDbgImageNames){
        const char* a=name; const char* b=img;
        while(*a && *b && WndLowerCh(*a)==WndLowerCh(*b)){ ++a; ++b; }
        if(*a==0 && *b==0) return true;
    }
    return false;
}
static bool WndTitleLooksLikeDebugger(const char* txt){
    return strstr(txt,"x64dbg")||strstr(txt,"x32dbg")||strstr(txt,"TitanEngine")||strstr(txt,"Scylla");
}
static void WndRegStore(HWND hWnd, const char* origTitle){
    HKEY hKey;
    if(RegCreateKeyExA(HKEY_CURRENT_USER, kWndRegKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr)!=ERROR_SUCCESS) return;
    char name[32]; snprintf(name,sizeof(name),"%llu",(unsigned long long)(uintptr_t)hWnd);
    RegSetValueExA(hKey, name, 0, REG_SZ, (const BYTE*)origTitle, (DWORD)strlen(origTitle)+1);
    RegCloseKey(hKey);
}
typedef BOOL (WINAPI* PSETAFF)(HWND, DWORD);
static PSETAFF WndGetSetAffinity(){
    static PSETAFF p = nullptr;
    if(!p) p = (PSETAFF)GetProcAddress(GetModuleHandleA("user32.dll"), "SetWindowDisplayAffinity");
    return p;
}
static BOOL CALLBACK WndHideEnumProc(HWND hWnd, LPARAM lParam){
    if(!WndIsDebuggerProcess(hWnd)) return TRUE;
    char txt[256]={0}; GetWindowTextA(hWnd, txt, sizeof(txt));
    if(!WndTitleLooksLikeDebugger(txt)) return TRUE;
    WndRegStore(hWnd, txt);
    SetWindowTextA(hWnd, "Calculator");
    PSETAFF p = WndGetSetAffinity();
    if(p) p(hWnd, 0x11);
    (*(int*)(intptr_t)lParam)++;
    return TRUE;
}
static BOOL CALLBACK WndRestoreEnumProc(HWND hWnd, LPARAM lParam){
    char name[32]; snprintf(name,sizeof(name),"%llu",(unsigned long long)(uintptr_t)hWnd);
    HKEY hKey;
    if(RegOpenKeyExA(HKEY_CURRENT_USER, kWndRegKey, 0, KEY_QUERY_VALUE, &hKey)!=ERROR_SUCCESS) return TRUE;
    char title[256]={0}; DWORD sz=sizeof(title);
    LSTATUS st = RegQueryValueExA(hKey, name, nullptr, nullptr, (BYTE*)title, &sz);
    RegCloseKey(hKey);
    if(st!=ERROR_SUCCESS) return TRUE;
    SetWindowTextA(hWnd, title);
    PSETAFF p = WndGetSetAffinity();
    if(p) p(hWnd, 0);
    RegDeleteKeyValueA(HKEY_CURRENT_USER, kWndRegKey, name);
    (*(int*)(intptr_t)lParam)++;
    return TRUE;
}
static void WndCleanupStaleEntries(){
    HKEY hKey;
    if(RegOpenKeyExA(HKEY_CURRENT_USER, kWndRegKey, 0, KEY_QUERY_VALUE|KEY_SET_VALUE, &hKey)!=ERROR_SUCCESS) return;
    DWORD idx=0;
    for(;;){
        char name[32]; DWORD nameLen=sizeof(name);
        LONG st = RegEnumValueA(hKey, idx, name, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if(st!=ERROR_SUCCESS) break;
        HWND hWnd=(HWND)(uintptr_t)strtoull(name,nullptr,10);
        if(!IsWindow(hWnd)) RegDeleteValueA(hKey, name);
        else ++idx;
    }
    RegCloseKey(hKey);
}
extern "C" {
NPT_API uint32_t NpT_DbgLink(uint32_t enable, uint32_t* renamedOut){
    int n=0;
    if(enable){ EnumWindows(WndHideEnumProc,(LPARAM)&n); }
    else { EnumWindows(WndRestoreEnumProc,(LPARAM)&n); WndCleanupStaleEntries(); }
    if(renamedOut) *renamedOut= (uint32_t)n;
    return 0;
}
} // extern C

// ---------------- BYOVD 安装链（移植 Win32 GuiDoDrvInstall，日志回传） ----------------
typedef void (CALLBACK* NPT_LOG_CB)(const wchar_t* line);
static void LogAppend(wchar_t* out, uint32_t cap, const wchar_t* line){
    if(!out||!cap) return;
    size_t cur = wcslen(out);
    if(cur+2 >= cap) return;
    _snwprintf(out+cur, cap-cur, L"%s\r\n", line);
    out[cap-1]=0;
}
// 流式日志回调：R3 注册后每条安装日志实时推给宿主（Rust 侧存静态 buffer 供前端轮询）
typedef void (CALLBACK* NPT_LOG_CB)(const wchar_t* line);
static NPT_LOG_CB g_logCb = nullptr;
static CRITICAL_SECTION g_logCs; static bool g_logCsInit = false;
static void LogEmit(const wchar_t* line){
    if(!g_logCsInit){ InitializeCriticalSection(&g_logCs); g_logCsInit = true; }
    EnterCriticalSection(&g_logCs);
    NPT_LOG_CB cb = g_logCb;
    LeaveCriticalSection(&g_logCs);
    if(cb) cb(line);
}
// npPath/hwPath 必须由调用方提供（云端驱动包解出的文件，DLL 用完即删）。
// v2 起 DLL 不再内嵌任何驱动字节（NPT_NO_EMBEDDED），无兜底。
static uint32_t DoInstall(const wchar_t* npPathIn, const wchar_t* hwPathIn, wchar_t* svcOut, uint32_t svcCap, wchar_t* logOut, uint32_t logCap){
    auto lg=[&](const wchar_t* l){ LogAppend(logOut,logCap,l); LogEmit(l); };
    if(!DrvIsAdmin()) return NPT_NEED_ADMIN;
    { SecFindings f=SecQueryAll(); if(f.any()) return NPT_SECGATE_BLOCKED; }
    if(!npPathIn || !*npPathIn || !hwPathIn || !*hwPathIn){
        lg(L"未提供云端驱动包文件：请先在卡密页下载驱动包");
        return 7;
    }
    std::wstring npPath = npPathIn, hwPath = hwPathIn;
    srand((unsigned)GetTickCount());
    wchar_t svc[64], hwSvc[32];
    swprintf(svc,64,L"NpHv_%u_%u",(unsigned)(GetTickCount()%100000),(unsigned)(rand()%1000));
    swprintf(hwSvc,32,L"HwRw%u",(unsigned)(rand()%100000));
    { wchar_t l[160]; wcscpy(l,L"BYOVD 安装 -> 服务 "); wcsncat(l,svc,160-wcslen(l)-1); lg(l); }
    if(!DrvScmLoad(hwPath,hwSvc)){
        DWORD e=GetLastError();
        wchar_t l[160]; swprintf(l,160,L"HwRwDrv 加载失败 NTSTATUS 0x%08X 可能被杀软拦截",(unsigned)e); lg(l);
        DeleteFileW(npPath.c_str()); DeleteFileW(hwPath.c_str()); return 4;
    }
    lg(L"HwRwDrv 已加载，正在 CI 补丁 (SeCiCallbacks -> ZwFlushInstructionCache)...");
    if(!CiPatchSeCiCallbacks()) lg(L"CI 补丁失败，仍尝试加载 NpHv (0xC0000428 预期)");
    else lg(L"CI 补丁成功");
    bool ok = DrvScmLoad(npPath,svc);
    DWORD errOk = GetLastError();
    CiRestoreSeCiCallbacks(); bool hwUnloaded=false,hwCleaned=false;
    hwUnloaded = DrvScmUnload(hwSvc); hwCleaned = (DeleteFileW(hwPath.c_str())!=0); lg((hwUnloaded&&hwCleaned)?L"漏洞驱动已卸载，临时文件已清理":L"漏洞驱动清理异常（服务/临时文件可能残留）");
    if(ok){
        wchar_t l[128]; wcscpy(l,L"BYOVD 安装成功 服务="); wcsncat(l,svc,128-wcslen(l)-1); lg(l);
        HKEY h; RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\NpHvCtl",0,NULL,0,KEY_WRITE,NULL,&h,NULL);
        RegSetValueExW(h,L"LastService",0,REG_SZ,(BYTE*)svc,(DWORD)((wcslen(svc)+1)*2)); RegCloseKey(h);
        DeleteFileW(npPath.c_str());
        NpT_Close(); NpT_Open();
        if(svcOut&&svcCap){ wcsncpy(svcOut,svc,svcCap-1); svcOut[svcCap-1]=0; }
        return 0;
    }
    wchar_t l[160]; swprintf(l,160,L"NpHv 加载失败 NTSTATUS 0x%08X (仍是0xC0000428说明CI补丁未生效)",(unsigned)errOk); lg(l);
    DeleteFileW(npPath.c_str());
    return 6;
}
extern "C" {
NPT_API void NpT_SetLogCallback(NPT_LOG_CB cb){
    if(!g_logCsInit){ InitializeCriticalSection(&g_logCs); g_logCsInit = true; }
    EnterCriticalSection(&g_logCs);
    g_logCb = cb;
    LeaveCriticalSection(&g_logCs);
}
NPT_API uint32_t NpT_Install(wchar_t* svcOut, uint32_t svcCap, wchar_t* logOut, uint32_t logCap){
    if(logOut&&logCap) logOut[0]=0;
    LogAppend(logOut,logCap,L"内嵌驱动已移除（v2 云端下发模式），请使用 NpT_InstallPkg");
    return 7;
}
NPT_API uint32_t NpT_InstallPkg(const wchar_t* npPath, const wchar_t* hwPath, wchar_t* svcOut, uint32_t svcCap, wchar_t* logOut, uint32_t logCap){
    if(logOut&&logCap) logOut[0]=0;
    return DoInstall(npPath, hwPath, svcOut, svcCap, logOut, logCap);
}
NPT_API uint32_t NpT_Uninstall(wchar_t* logOut, uint32_t logCap){
    if(logOut&&logCap) logOut[0]=0;
    auto lg=[&](const wchar_t* l){ LogAppend(logOut,logCap,l); LogEmit(l); };
    if(!DrvIsAdmin()) return NPT_NEED_ADMIN;
    wchar_t svc[128]={0}; DWORD cb=sizeof(svc); HKEY h;
    if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\NpHvCtl",0,KEY_READ,&h)==ERROR_SUCCESS){ RegQueryValueExW(h,L"LastService",NULL,NULL,(BYTE*)svc,&cb); RegCloseKey(h); }
    const wchar_t* targets[4] = { svc[0]?svc:L"NpHv", L"NpHv", L"drv0", L"drv1" };
    uint32_t n=0;
    for(int i=0;i<4;i++){
        if(!targets[i][0]) continue;
        if(i>0 && svc[0] && wcscmp(targets[i],svc)==0) continue;
        if(DrvScmUnload(targets[i])){ wchar_t l[96]; swprintf(l,96,L"已卸载 %s",targets[i]); lg(l); n++; }
    }
    lg(L"已尝试卸载 Hypervisor");
    if(!n) lg(L"未找到已安装的驱动服务");
    NpT_Close();
    return n;
}
} // extern C

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID){ return TRUE; }





