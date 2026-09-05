#pragma once
#include <windows.h>
#include <cstdint>

#define HC_PING 0x4E505640ULL
#define HC_QUERY_STATUS 0x4E505641ULL
#define HC_GET_DEVICE_NAME 0x4E505642ULL
#define HC_DBG_HIDE 0x4E505643ULL
#define HC_DBG_PROTECT 0x4E505644ULL
#define HC_DBG_MODE 0x4E505645ULL
static const uint64_t HC_COOKIE = 0x5A; static uint64_t g_HcCookie = 0x5A; // set after AuthGate, rolling low byte
inline void HcSetCookie(uint64_t c){ g_HcCookie = c; }

static LONG CALLBACK HcVeh(struct _EXCEPTION_POINTERS* ep){
    ULONG code = ep->ExceptionRecord->ExceptionCode;
    if(code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_PRIV_INSTRUCTION){
        ep->ContextRecord->Rip += 3;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

inline bool HcPing(){
    PVOID h = AddVectoredExceptionHandler(1, HcVeh);
    uint64_t rax = HC_PING ^ (HC_COOKIE & 0xFF);
    __asm__ volatile("vmmcall" : "+a"(rax) : : "rbx","rcx","rdx","r8","r9","r10","r11","memory");
    RemoveVectoredExceptionHandler(h);
    return rax == 0x4E505641ULL;
}

inline bool HcGetDeviceName(wchar_t* out, size_t outChars){
    PVOID h = AddVectoredExceptionHandler(1, HcVeh);
    uint64_t origRax = (HC_GET_DEVICE_NAME ^ (g_HcCookie & 0xFF));
    uint64_t rax = origRax, rbx=0, rcx=0, rdx=0, r8v=0, r9v=0, r10v=0, r11v=0;
    __asm__ volatile("vmmcall" : "+a"(rax), "+b"(rbx), "+c"(rcx), "+d"(rdx), "+r"(r8v), "+r"(r9v), "+r"(r10v), "+r"(r11v) : : "memory");
    RemoveVectoredExceptionHandler(h);
    if(rax == origRax) return false; // hypervisor not present (vmmcall was skipped)
    if((int64_t)rax <0 || rax==0xC0000001) return false;
    size_t len = (size_t)rax; if(len>= outChars*2) len = (outChars-1)*2;
    unsigned char tmp[56]; *(uint64_t*)&tmp[0]=rbx; *(uint64_t*)&tmp[8]=rcx; *(uint64_t*)&tmp[16]=rdx; *(uint64_t*)&tmp[24]=r8v; *(uint64_t*)&tmp[32]=r9v; *(uint64_t*)&tmp[40]=r10v; *(uint64_t*)&tmp[48]=r11v;
    memcpy(out, tmp, len); out[len/2]=0;
    return true;
}
inline bool HcDbgHide(bool enable){
    PVOID h = AddVectoredExceptionHandler(1, HcVeh);
    uint64_t origRax = (HC_DBG_HIDE ^ (g_HcCookie & 0xFF));
    uint64_t rax = origRax, rbx = enable?1:0, rcx=0, rdx=0, r8v=0, r9v=0, r10v=0, r11v=0;
    __asm__ volatile("vmmcall" : "+a"(rax), "+b"(rbx), "+c"(rcx), "+d"(rdx), "+r"(r8v), "+r"(r9v), "+r"(r10v), "+r"(r11v) : : "memory");
    RemoveVectoredExceptionHandler(h);
    if(rax == origRax) return false;
    if((int64_t)rax == 0 || (int64_t)rax == 0x103) return true;
    return false;
}
inline bool HcDbgProtect(uint32_t pid, bool protect){
    PVOID h = AddVectoredExceptionHandler(1, HcVeh);
    uint64_t origRax = (HC_DBG_PROTECT ^ (g_HcCookie & 0xFF));
    uint64_t rax = origRax, rbx = pid, rcx = protect?1:0;
    __asm__ volatile("vmmcall" : "+a"(rax), "+b"(rbx), "+c"(rcx) : : "rdx","r8","r9","r10","r11","memory");
    RemoveVectoredExceptionHandler(h);
    if(rax == origRax) return false;
    return (int64_t)rax == 0 || (int64_t)rax == 0x103;
}
inline bool HcDbgMode(uint32_t mode){
    PVOID h = AddVectoredExceptionHandler(1, HcVeh);
    uint64_t origRax = (HC_DBG_MODE ^ (g_HcCookie & 0xFF));
    uint64_t rax = origRax, rbx = mode;
    __asm__ volatile("vmmcall" : "+a"(rax), "+b"(rbx) : : "rcx","rdx","r8","r9","r10","r11","memory");
    RemoveVectoredExceptionHandler(h);
    if(rax == origRax) return false;
    return (int64_t)rax == 0 || (int64_t)rax == 0x103;
}
inline bool HcQueryStatus(void* out, size_t len){
    if(len < 24) return false;
    PVOID h = AddVectoredExceptionHandler(1, HcVeh);
    uint64_t rax = (HC_QUERY_STATUS ^ (HC_COOKIE & 0xFF)), rbx=0, rcx=0, rdx=0, r8v=0, r9v=0, r10v=0;
    __asm__ volatile("vmmcall"
        : "+a"(rax), "+b"(rbx), "+c"(rcx), "+d"(rdx), "+r"(r8v), "+r"(r9v), "+r"(r10v)
        :
        : "r11","memory");
    RemoveVectoredExceptionHandler(h);
    if(rax != 0) return false;
    struct S { uint32_t Version; uint32_t Running; uint32_t ProcCount; uint32_t Active; uint32_t Retired; uint32_t Flags; };
    S* s = (S*)out;
    s->Version = (uint32_t)rbx;
    s->Running = (uint32_t)rcx;
    s->ProcCount = (uint32_t)rdx;
    s->Active = (uint32_t)r8v;
    s->Retired = (uint32_t)r9v;
    s->Flags = (uint32_t)r10v;
    return true;
}
