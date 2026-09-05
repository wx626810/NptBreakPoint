#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
// NPT_NO_EMBEDDED：Tauri 传输层 DLL 构建时定义，驱动字节改为云端下发，
// 不再把 NpHv/HwRw 编进二进制。Win32 NpHvCtl.exe 等旧链路不受影响。
#ifndef NPT_NO_EMBEDDED
#include "embedded_drivers.h"
#endif

inline bool DrvIsAdmin() {
    BOOL isAdmin=FALSE; PSID sid=NULL; SID_IDENTIFIER_AUTHORITY auth=SECURITY_NT_AUTHORITY;
    if(AllocateAndInitializeSid(&auth,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)){
        CheckTokenMembership(NULL,sid,&isAdmin); FreeSid(sid);
    }
    return isAdmin==TRUE;
}
inline bool DrvRequestAdmin(const wchar_t* params) {
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL,exe,MAX_PATH);
    SHELLEXECUTEINFOW sei{}; sei.cbSize=sizeof(sei); sei.lpVerb=L"runas"; sei.lpFile=exe; sei.lpParameters=params; sei.nShow=SW_SHOWNORMAL;
    if(!ShellExecuteExW(&sei)) return false;
    ExitProcess(0); return true;
}
inline std::wstring DrvTempPath(){ wchar_t b[MAX_PATH]; GetTempPathW(MAX_PATH,b); return b; }
#ifdef NPT_NO_EMBEDDED
// 云端下发模式：不内嵌驱动，提取函数不可用（编译期排除，字节不进二进制）
#else
inline bool DrvExtractHw(std::wstring &outPath) {
    wchar_t rnd[16]; swprintf(rnd,16,L"%08X",(unsigned)rand());
    std::wstring dst=DrvTempPath()+L"HwRw"+rnd+L".sys";
    // decrypt on stack (XOR 0x5A + i)
    unsigned char* buf=(unsigned char*)HeapAlloc(GetProcessHeap(),0,g_HwRwBytes_len);
    if(!buf) return false;
    for(unsigned i=0;i<g_HwRwBytes_len;i++) buf[i]= g_HwRwBytes[i] ^ 0x5A ^ (i & 0xFF);
    HANDLE h=CreateFileW(dst.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h==INVALID_HANDLE_VALUE){ HeapFree(GetProcessHeap(),0,buf); return false; }
    DWORD w=0; WriteFile(h, buf, g_HwRwBytes_len, &w, NULL); CloseHandle(h);
    SecureZeroMemory(buf,g_HwRwBytes_len); HeapFree(GetProcessHeap(),0,buf);
    if(w!=g_HwRwBytes_len){ DeleteFileW(dst.c_str()); return false; }
    outPath=dst; return true;
}
inline bool DrvExtractNpHv(std::wstring &outPath){
    wchar_t rnd[16]; swprintf(rnd,16,L"%08X",(unsigned)rand());
    std::wstring dst=DrvTempPath()+L"NpHv"+rnd+L".sys";
    unsigned char* buf=(unsigned char*)HeapAlloc(GetProcessHeap(),0,g_NpHvBytes_len);
    if(!buf) return false;
    for(unsigned i=0;i<g_NpHvBytes_len;i++) buf[i]= g_NpHvBytes[i] ^ 0x5A ^ (i & 0xFF);
    HANDLE h=CreateFileW(dst.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h==INVALID_HANDLE_VALUE){ HeapFree(GetProcessHeap(),0,buf); return false; }
    DWORD w=0; WriteFile(h, buf, g_NpHvBytes_len, &w, NULL); CloseHandle(h);
    SecureZeroMemory(buf,g_NpHvBytes_len); HeapFree(GetProcessHeap(),0,buf);
    if(w!=g_NpHvBytes_len){ DeleteFileW(dst.c_str()); return false; }
    outPath=dst; return true;
}
#endif // NPT_NO_EMBEDDED
inline bool DrvSetupReg(const std::wstring& svc,const std::wstring& path){
    std::wstring reg=L"SYSTEM\\CurrentControlSet\\Services\\"+svc; HKEY h; if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,reg.c_str(),0,NULL,0,KEY_ALL_ACCESS,NULL,&h,NULL)!=ERROR_SUCCESS) return false;
    DWORD t=1,e=1; RegSetValueExW(h,L"Type",0,REG_DWORD,(BYTE*)&t,4); RegSetValueExW(h,L"ErrorControl",0,REG_DWORD,(BYTE*)&e,4);
    std::wstring img=L"\\??\\"+path; RegSetValueExW(h,L"ImagePath",0,REG_SZ,(BYTE*)img.c_str(),(DWORD)((img.size()+1)*2)); RegCloseKey(h); return true;
}
inline bool DrvRemoveReg(const std::wstring& svc){ std::wstring reg=L"SYSTEM\\CurrentControlSet\\Services\\"+svc; return RegDeleteKeyW(HKEY_LOCAL_MACHINE,reg.c_str())==ERROR_SUCCESS; }
inline bool DrvEnablePriv(const wchar_t* name){
    HANDLE tok; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tok)) return false;
    LUID luid; if(!LookupPrivilegeValueW(NULL,name,&luid)){CloseHandle(tok);return false;}
    TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid; tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    bool ok=AdjustTokenPrivileges(tok,FALSE,&tp,0,NULL,NULL) && GetLastError()==ERROR_SUCCESS; CloseHandle(tok); return ok;
}
inline bool DrvScmLoad(const std::wstring& sysPath,const std::wstring& svc){
    if(!DrvEnablePriv(L"SeLoadDriverPrivilege")) return false;
    if(!DrvSetupReg(svc,sysPath)) return false;
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    auto NtLoadDriver=(LONG(NTAPI*)(PUNICODE_STRING))GetProcAddress(ntdll,"NtLoadDriver");
    auto RtlInitUnicodeString=(void(NTAPI*)(PUNICODE_STRING,PCWSTR))GetProcAddress(ntdll,"RtlInitUnicodeString");
    if(!NtLoadDriver||!RtlInitUnicodeString){ DrvRemoveReg(svc); return false; }
    std::wstring s=L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"+svc; UNICODE_STRING u; RtlInitUnicodeString(&u,s.c_str());
    LONG st=NtLoadDriver(&u); if(st==0xC000010E) return true; if(st>=0) return true; DrvRemoveReg(svc); SetLastError((DWORD)st); return false;
}
inline bool DrvScmUnload(const std::wstring& svc){
    DrvEnablePriv(L"SeLoadDriverPrivilege");
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    auto NtUnloadDriver=(LONG(NTAPI*)(PUNICODE_STRING))GetProcAddress(ntdll,"NtUnloadDriver");
    auto RtlInitUnicodeString=(void(NTAPI*)(PUNICODE_STRING,PCWSTR))GetProcAddress(ntdll,"RtlInitUnicodeString");
    if(!NtUnloadDriver||!RtlInitUnicodeString) return false;
    std::wstring s=L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"+svc; UNICODE_STRING u; RtlInitUnicodeString(&u,s.c_str());
    LONG st=NtUnloadDriver(&u); DrvRemoveReg(svc); return (st>=0) || st==(LONG)0xC0000034;
}
