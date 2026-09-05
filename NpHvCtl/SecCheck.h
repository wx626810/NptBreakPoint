#pragma once
// 安装前置安全检查：VBS / HVCI（内存完整性）/ Defender 实时防护。
// 开启则要求用户手动关闭后重试 — 本驱动是自研 SVM hypervisor，
// 与 Hyper-V/VBS 互斥；HVCI 会拦签名链；Defender 会拦 BYOVD + 物理内存驱动。
#include <windows.h>
#include <stdio.h>
#include <string>

inline std::string SecToLower(std::string s){
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] += 32;
    return s;
}

// 捕获命令输出（一次性行为，安装前点一下，几秒延迟可接受）
inline std::string SecRunCapture(const char* cmd){
    std::string out;
    HANDLE hR=nullptr,hW=nullptr; SECURITY_ATTRIBUTES csa{}; csa.nLength=sizeof(csa); csa.bInheritHandle=TRUE; if(!CreatePipe(&hR,&hW,&csa,0)) return out;
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0); wchar_t wcmd[1024]={0}; MultiByteToWideChar(CP_ACP,0,cmd,-1,wcmd,1024);
    wchar_t cl[1152]={0}; wcscpy(cl,L"cmd.exe /c "); wcsncat(cl,wcmd,1152-wcslen(cl)-1);
    STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.hStdOutput=hW; si.hStdError=hW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi{}; if(CreateProcessW(NULL,cl,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){ CloseHandle(hW); hW=nullptr; char buf[256]; DWORD r=0;
    while(ReadFile(hR,buf,sizeof(buf)-1,&r,NULL)&&r){ buf[r]=0; out+=buf; } WaitForSingleObject(pi.hProcess,15000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); } if(hW) CloseHandle(hW); CloseHandle(hR); return out;
}

inline bool SecRegDword(HKEY root, const wchar_t* key, const wchar_t* val, DWORD& out){
    HKEY h;
    if (RegOpenKeyExW(root, key, 0, KEY_READ, &h) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = sizeof(DWORD);
    LONG st = RegQueryValueExW(h, val, nullptr, &type, (BYTE*)&out, &size);
    RegCloseKey(h);
    return st == ERROR_SUCCESS && type == REG_DWORD;
}

// VBS 运行中：Win32_DeviceGuard.VirtualizationBasedSecurityStatus == 2
inline bool SecQueryVbs(){
    std::string o = SecToLower(SecRunCapture(
        "powershell -NoProfile -NonInteractive -Command "
        "\"(Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard "
        "-ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus\" 2>nul"));
    return o.find('2') != std::string::npos;
}

// HVCI 运行中：SecurityServicesRunning 包含 2
inline bool SecQueryHvci(){
    std::string o = SecToLower(SecRunCapture(
        "powershell -NoProfile -NonInteractive -Command "
        "\"(Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard "
        "-ClassName Win32_DeviceGuard).SecurityServicesRunning -contains 2\" 2>nul"));
    return o.find("true") != std::string::npos;
}

// Defender 实时防护：Get-MpComputerStatus，失败回退注册表（DisableRealtimeMonitoring）
inline bool SecQueryDefenderRt(){
    std::string o = SecToLower(SecRunCapture(
        "powershell -NoProfile -NonInteractive -Command "
        "\"(Get-MpComputerStatus).RealTimeProtectionEnabled\" 2>nul"));
    if (o.find("true") != std::string::npos) return true;
    if (o.find("false") != std::string::npos) return false;
    DWORD v = 0;
    if (SecRegDword(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                    L"DisableRealtimeMonitoring", v))
        return v != 1;   // 未显式禁用 = 视为开启
    return true;         // 查询全失败 = 保守视为开启
}

struct SecFindings { bool vbs, hvci, defender; bool any() const { return vbs || hvci || defender; } };

inline SecFindings SecQueryAll(){
    SecFindings f;
    f.vbs = SecQueryVbs();
    f.hvci = SecQueryHvci();
    f.defender = SecQueryDefenderRt();
    return f;
}

inline void SecBuildMessage(const SecFindings& f, wchar_t* msg, size_t cch){
    std::wstring m = L"检测到以下安全功能开启，必须手动关闭后才能安装：\n\n";
    if (f.vbs)  m += L"[VBS] 基于虚拟化的安全：与本驱动 (自研 Hypervisor) 互斥\n"
                     L"  关闭：管理员 CMD 执行  bcdedit /set hypervisorlaunchtype off  并重启\n\n";
    if (f.hvci) m += L"[HVCI] 内核隔离/内存完整性：会拦截签名链\n"
                     L"  关闭：Windows 安全中心 -> 设备安全性 -> 内核隔离 -> 关闭内存完整性 -> 重启\n\n";
    if (f.defender) m += L"[Defender] 病毒与威胁防护实时保护：会拦截 BYOVD/物理内存驱动\n"
                     L"  关闭：Windows 安全中心 -> 病毒和威胁防护 -> 管理设置 -> 关闭实时保护\n\n";
    m += L"关闭（可能需要重启）后点\"重试\"重新检测；点\"取消\"放弃安装。";
    _snwprintf(msg, cch, L"%s", m.c_str());
    msg[cch-1] = 0;
}

// GUI：循环 检测->提示->(重试/取消)，通过返回 true
inline bool SecGateGui(){
    for (;;){
        SecFindings f = SecQueryAll();
        if (!f.any()) return true;
        wchar_t msg[1400];
        SecBuildMessage(f, msg, 1400);
        int r = MessageBoxW(nullptr, msg, L"NptBP - 安装前需手动关闭安全功能",
                            MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON1 | MB_TOPMOST);
        if (r != IDOK) return false;
    }
}

// CLI：打印提示，返回 false 放弃安装
inline bool SecGateCli(){
    SecFindings f = SecQueryAll();
    if (!f.any()) return true;
    printf("[sec] precheck FAILED:\n");
    if (f.vbs)     printf("  [x] VBS running        -> bcdedit /set hypervisorlaunchtype off + reboot\n");
    if (f.hvci)    printf("  [x] HVCI (core isol.)  -> Windows Security -> Core isolation -> off + reboot\n");
    if (f.defender)printf("  [x] Defender realtime  -> Windows Security -> Virus protection -> off\n");
    printf("[sec] 关闭后重新运行安装。本次安装取消。\n");
    return false;
}






