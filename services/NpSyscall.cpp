/*!
    @file       NpSyscall.cpp

    @brief      P0：syscall 号提取 + SSDT 定位/条目读取（共享模块）。

    @details    从 NpDebugHide.cpp 抽离（2026-08-27 报告 §3.1）：
                - ntdll stub 提取 syscall 号（mov eax, imm32）；
                - 双锚点 + 表特征扫描定位 KiServiceTable（4B RVA / 8B 绝对，
                  抗 SSDT hook）；
                - 4B/8B 条目读取（4B = 模块基址 + RVA，实测语义）；
                - Nt/Zw 多策略解析（导出表 → Zw 别名 → SSDT 兜底）；
                - LSTAR 拦截表（NpLstar 初始化时查询）。

                跨版本只依赖 syscall 号与 KiServiceTable 结构（Win10 1903+
                4B / 老版本 8B 自动判别）。
 */
#define POOL_NX_OPTIN 1
#include "NpSyscall.h"
#include "NpLog.h"
#include <ntimage.h>
#include <intrin.h>

extern "C" PLIST_ENTRY PsLoadedModuleList;
extern "C" PVOID PsGetProcessPeb(PEPROCESS Process);
// WDK 内核头不引入 ZwQuerySystemInformation 声明。
#define SystemProcessInformation 5
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef struct _NP_LDR2 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} NP_LDR2;

//
// LSTAR 拦截表（P2/P3 全量语义）。NpSyscallInitialize 时解析 syscall 号，
// NpSyscallIsIntercepted 供跳板生成器使用。
//
static const char *const g_InterceptNames[] = {
    "NtDebugActiveProcess",
    "NtRemoveProcessDebug",
    "NtWaitForDebugEvent",
    "NtWaitForDebugEventEx",
    "NtDebugContinue",
    "NtQueryInformationProcess",
    "NtSuspendThread",
    "NtResumeThread",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
};
// Fallback table for Win11 24H2 26100.1 (hard-coded, PASSIVE_LEVEL file path is primary)
// Values verified via TestSyscall on 26100 host (see dump_syscalls)
static struct { const char* Name; ULONG Number; } g_FallbackNumbers[] = {
    { "NtDebugActiveProcess",       214 },
    { "NtRemoveProcessDebug",       384 },
    { "NtWaitForDebugEvent",        484 },
    { "NtWaitForDebugEventEx",      0   }, // not exported on 26100
    { "NtDebugContinue",            215 },
    { "NtQueryInformationProcess",  25  },
    { "NtSuspendThread",            463 },
    { "NtResumeThread",             82  },
    { "NtGetContextThread",         251 },
    { "NtSetContextThread",         410 },
    { "NtReadVirtualMemory",        63  },
    { "NtWriteVirtualMemory",       58  },
    { "NtQuerySystemInformation",   54  }, // dynamic QSI
};
static ULONG SFallbackNumber(const char* NtName) {
    if (!NtName) return 0;
    for (ULONG i=0;i<sizeof(g_FallbackNumbers)/sizeof(g_FallbackNumbers[0]);i++) {
        if (strcmp(g_FallbackNumbers[i].Name, NtName)==0) return g_FallbackNumbers[i].Number;
    }
    return 0;
}
// Forward decl for file fallback
static ULONG SExtractViaFile(const char* NtName);

#define NP_INTERCEPT_COUNT (sizeof(g_InterceptNames) / sizeof(g_InterceptNames[0]))
#define NP_INTERCEPT_MAX   32

static ULONG g_InterceptNumbers[NP_INTERCEPT_MAX];
static ULONG g_InterceptNumberCount = 0;
// 动态拦截（prochide QSI）：刷新基础表后必须保留。
static ULONG g_DynamicNumbers[8];
static ULONG g_DynamicCount = 0;
// 基础拦截表 syscall 号缓存：首次从 ntdll 解析后不再依赖用户进程，
// 驱动加载期/后台线程刷新可脱离 ntdll 直接使用。
static ULONG g_BaseNumbers[NP_INTERCEPT_COUNT];
static BOOLEAN g_BaseResolved = FALSE;

static ULONG NpSyscallGetCachedNumber(const char *NtName)
{
    if (!g_BaseResolved || NtName == nullptr) return 0;
    for (ULONG i = 0; i < NP_INTERCEPT_COUNT; i++)
    {
        if (g_InterceptNames[i] != nullptr &&
            strcmp(g_InterceptNames[i], NtName) == 0)
        {
            return g_BaseNumbers[i];
        }
    }
    return 0;
}

// KiServiceTable 定位缓存：首次全镜像扫描后复用，避免每次刷新
// 对 8 个 Nt* 各扫一遍 ntoskrnl（嵌套虚拟化下极慢，会卡死 GUI）。
static ULONG_PTR g_ServiceTable = 0;
static ULONG_PTR g_ServiceMb = 0;
static BOOLEAN g_ServiceIs4 = FALSE;
static BOOLEAN g_ServiceCacheValid = FALSE;

//
// ============================ 模块/导出解析 ============================
//

static PVOID SGetExport(PVOID Base, const char *Name) {
    if (!Base) return nullptr;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        PIMAGE_NT_HEADERS64 nh = (PIMAGE_NT_HEADERS64)((PUCHAR)Base + dos->e_lfanew);
        if (nh->Signature != IMAGE_NT_SIGNATURE ||
            nh->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
        ULONG rva = nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) return nullptr;
        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Base + rva);
        PULONG names = (PULONG)((PUCHAR)Base + exp->AddressOfNames);
        PUSHORT ords = (PUSHORT)((PUCHAR)Base + exp->AddressOfNameOrdinals);
        PULONG funcs = (PULONG)((PUCHAR)Base + exp->AddressOfFunctions);
        for (ULONG i = 0; i < exp->NumberOfNames; i++) {
            const char *n = (const char *)((PUCHAR)Base + names[i]);
            if (strcmp(n, Name) == 0) return (PUCHAR)Base + funcs[ords[i]];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return nullptr;
}

static PVOID SGetModuleBaseFromPeb(PCWSTR ModuleName) {
    if (KeGetCurrentIrql() > APC_LEVEL) return nullptr;
    UNICODE_STRING target;
    RtlInitUnicodeString(&target, ModuleName);
    PVOID peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb || !MmIsAddressValid(peb)) return nullptr;
    if (peb) {
        __try {
            PVOID ldr = *(PVOID *)((PUCHAR)peb + 0x18);
            PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)ldr + 0x10);
            for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
                NP_LDR2 *m = CONTAINING_RECORD(e, NP_LDR2, InLoadOrderLinks);
                if (RtlCompareUnicodeString(&m->BaseDllName, &target, TRUE) == 0)
                    return m->DllBase;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return nullptr;
}

static PVOID SGetModuleBaseFromList(PCWSTR ModuleName) {
    UNICODE_STRING target;
    RtlInitUnicodeString(&target, ModuleName);
    if (PsLoadedModuleList == nullptr) return nullptr;
    for (PLIST_ENTRY e = PsLoadedModuleList->Flink;
         e != PsLoadedModuleList; e = e->Flink) {
        NP_LDR2 *m = CONTAINING_RECORD(e, NP_LDR2, InLoadOrderLinks);
        if (RtlCompareUnicodeString(&m->BaseDllName, &target, TRUE) == 0)
            return m->DllBase;
    }
    return nullptr;
}

static PVOID SGetNtdllBase() {
    // 不缓存：驱动加载期在 System 进程（无 ntdll），必须允许后续
    // 在用户进程上下文（NpHvCtl IOCTL）重新解析。
    PVOID b = SGetModuleBaseFromPeb(L"ntdll.dll");
    if (b == nullptr) b = SGetModuleBaseFromList(L"ntdll.dll");
    return b;
}

// 驱动加载期（System 进程）无 ntdll：附加到任意用户进程读其 PEB。
static BOOLEAN SResolveNtdllFromUserProcess(void)
{
    BOOLEAN ok = FALSE;
    ULONG need = 0x40000;
    for (ULONG round = 0; round < 6 && !ok; round++)
    {
        PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'ySNp');
        if (!buf) break;
        ULONG returned = 0;
        NTSTATUS st = ZwQuerySystemInformation(SystemProcessInformation,
                                               buf, need, &returned);
        if (st == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(buf, 'ySNp');
            need = returned ? returned + 0x1000 : need * 2;
            continue;
        }
        if (!NT_SUCCESS(st))
        {
            ExFreePoolWithTag(buf, 'ySNp');
            break;
        }

        PUCHAR p = (PUCHAR)buf;
        for (;;)
        {
            ULONG next = *(PULONG)p;
            HANDLE pid = *(PHANDLE)(p + 0x08);
            ULONG pidVal = (ULONG)(ULONG_PTR)pid;
            if (pidVal != 0 && pidVal != 4)
            {
                PEPROCESS proc = nullptr;
                if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc)) &&
                    proc != nullptr)
                {
                    if (PsGetProcessPeb(proc) != nullptr)
                    {
                        KAPC_STATE apc;
                        KeStackAttachProcess(proc, &apc);
                        ok = (SGetModuleBaseFromPeb(L"ntdll.dll") != nullptr);
                        KeUnstackDetachProcess(&apc);
                    }
                    ObDereferenceObject(proc);
                    if (ok) break;
                }
            }
            if (next == 0) break;
            p += next;
        }
        ExFreePoolWithTag(buf, 'ySNp');
    }
    return ok;
}

// 附着任意带 PEB 的用户进程执行回调（驱动加载期 System 上下文用）。
BOOLEAN NpSyscallRunInUserContext(void (*Callback)(void *Context), void *Context)
{
    if (Callback == nullptr) return FALSE;

    ULONG need = 0x40000;
    for (ULONG round = 0; round < 6; round++)
    {
        PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'ySNp');
        if (buf == nullptr) return FALSE;

        ULONG returned = 0;
        NTSTATUS st = ZwQuerySystemInformation(SystemProcessInformation,
                                               buf, need, &returned);
        if (st == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(buf, 'ySNp');
            need = returned ? returned + 0x1000 : need * 2;
            continue;
        }
        if (!NT_SUCCESS(st))
        {
            ExFreePoolWithTag(buf, 'ySNp');
            break;
        }

        PUCHAR p = static_cast<PUCHAR>(buf);
        for (;;)
        {
            ULONG next = *(PULONG)p;
            HANDLE pid = *(PHANDLE)(p + 0x08);
            ULONG pidVal = (ULONG)(ULONG_PTR)pid;
            if (pidVal != 0 && pidVal != 4)
            {
                PEPROCESS proc = nullptr;
                if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc)) &&
                    proc != nullptr)
                {
                    if (PsGetProcessPeb(proc) != nullptr)
                    {
                        KAPC_STATE apc;
                        KeStackAttachProcess(proc, &apc);
                        Callback(Context);
                        KeUnstackDetachProcess(&apc);
                        ObDereferenceObject(proc);
                        ExFreePoolWithTag(buf, 'ySNp');
                        return TRUE;
                    }
                    ObDereferenceObject(proc);
                }
            }
            if (next == 0) break;
            p += next;
        }
        ExFreePoolWithTag(buf, 'ySNp');
    }
    return FALSE;
}

ULONG NpSyscallExtractNumber(const char *NtName) {
    ULONG cached = NpSyscallGetCachedNumber(NtName);
    if (cached != 0) return cached;
    if (KeGetCurrentIrql() > APC_LEVEL) return SFallbackNumber(NtName);
    PVOID b = SGetNtdllBase();
    if (b) {
        PUCHAR s = (PUCHAR)SGetExport(b, NtName);
        if (s) {
            for (ULONG i = 0; i + 5 <= 0x40; i++)
                if (s[i] == 0xB8) return *(ULONG *)(s + i + 1);
        }
    }
    // Hard-coded fallback for 26100.1 (no file I/O to avoid BSOD at boot)
    return SFallbackNumber(NtName);
}

PVOID NpSyscallResolveAddress(const char *NtName) {
    ANSI_STRING a;
    UNICODE_STRING u;
    RtlInitAnsiString(&a, NtName);
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&u, &a, TRUE))) return nullptr;
    PVOID p = MmGetSystemRoutineAddress(&u);
    RtlFreeUnicodeString(&u);
    return p;
}

//
// ============================ SSDT 安全读取 ============================
//

static BOOLEAN SSafeReadBytes(ULONG_PTR Src, PVOID Dst, ULONG Length) {
    if (Src == 0 || Dst == nullptr || Length == 0) return FALSE;
    for (ULONG off = 0; off < Length; off += PAGE_SIZE) {
        if (!MmIsAddressValid((PVOID)(Src + off))) return FALSE;
    }
    __try {
        RtlCopyMemory(Dst, (PVOID)Src, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN SValidateImage(ULONG_PTR Base, ULONG_PTR MustContain) {
    LONG e_lfanew = 0;
    ULONG sig = 0;
    USHORT optMagic = 0;
    ULONG sizeOfImage = 0;
    if (!SSafeReadBytes(Base + 0x3C, &e_lfanew, sizeof(e_lfanew)) ||
        e_lfanew <= 0 || e_lfanew > 0x1000) return FALSE;
    if (!SSafeReadBytes(Base + e_lfanew, &sig, sizeof(sig)) ||
        (sig & 0xFFFF) != 0x4550) return FALSE;
    if (!SSafeReadBytes(Base + e_lfanew + 0x18, &optMagic, sizeof(optMagic)) ||
        optMagic != 0x20B) return FALSE;
    BOOLEAN hasSize = SSafeReadBytes(Base + e_lfanew + 0x38, &sizeOfImage,
                                     sizeof(sizeOfImage));
    if (hasSize && (sizeOfImage < 0x100000 || sizeOfImage > 0x10000000))
        hasSize = FALSE;
    if (MustContain != 0 && hasSize &&
        (MustContain < Base || MustContain >= Base + sizeOfImage))
        return FALSE;
    return TRUE;
}

// 从 PE 头读可执行段（.text 等）的 RVA 范围，用于过滤伪 SSDT 表。
static BOOLEAN SGetExecutableRange(ULONG_PTR Mz,
                                   PULONG_PTR OutStart,
                                   PULONG_PTR OutEnd)
{
    LONG e_lfanew = 0;
    ULONG sig = 0;
    USHORT optSize = 0;
    ULONG numSections = 0;

    if (!SSafeReadBytes(Mz + 0x3C, &e_lfanew, sizeof(e_lfanew)) ||
        e_lfanew <= 0 || e_lfanew > 0x1000) return FALSE;
    if (!SSafeReadBytes(Mz + e_lfanew, &sig, sizeof(sig)) ||
        (sig & 0xFFFF) != 0x4550) return FALSE;
    if (!SSafeReadBytes(Mz + e_lfanew + 0x14, &optSize, sizeof(optSize)) ||
        !SSafeReadBytes(Mz + e_lfanew + 6, &numSections, sizeof(numSections)))
        return FALSE;
    if (optSize > 0x400 || numSections == 0 || numSections > 96) return FALSE;

    ULONG_PTR secBase = Mz + e_lfanew + 24 + optSize;
    ULONG_PTR bestStart = 0;
    ULONG_PTR bestSize = 0;
    for (ULONG i = 0; i < numSections; i++)
    {
        ULONG_PTR sec = secBase + (ULONG_PTR)i * 40;
        ULONG vsize = 0, vaddr = 0, chars = 0;
        if (!SSafeReadBytes(sec + 8, &vsize, sizeof(vsize)) ||
            !SSafeReadBytes(sec + 12, &vaddr, sizeof(vaddr)) ||
            !SSafeReadBytes(sec + 36, &chars, sizeof(chars)))
            continue;
        if ((chars & IMAGE_SCN_MEM_EXECUTE) != 0 && vsize > bestSize)
        {
            bestStart = vaddr;
            bestSize = vsize;
        }
    }
    if (bestStart == 0 || bestSize == 0) return FALSE;
    *OutStart = bestStart;
    *OutEnd = bestStart + bestSize;
    return TRUE;
}

// 测量 4B 表候选位置处连续“代码 RVA”的段长（可跨页）。
// 要求候选必须是段起点（前一项不是代码 RVA）——真实 KiServiceTable
// 起点唯一，内部任意 4B 对齐命中会因此得 0 分被淘汰。
static ULONG SMeasureRvaRun(ULONG_PTR TableVa, ULONG_PTR TextStart,
                            ULONG_PTR TextEnd, ULONG_PTR Mz, ULONG_PTR End)
{
    if (TableVa >= Mz + 4)
    {
        LONG pv = 0;
        if (!SSafeReadBytes(TableVa - 4, &pv, sizeof(pv))) return 0;
        ULONG upv = (ULONG)(pv >> 4);        // Win11 表项 = RVA<<4 | flags
        if (upv >= TextStart && upv < TextEnd) return 0;   // 非段起点
    }

    ULONG run = 0;
    for (ULONG_PTR p = TableVa; p + 4 <= End; p += 4)
    {
        LONG ev = 0;
        if (!SSafeReadBytes(p, &ev, sizeof(ev))) break;
        ULONG uv = (ULONG)(ev >> 4);
        if (uv < TextStart || uv >= TextEnd) break;
        run++;
    }
    return run;
}

// 只向前测量连续代码 RVA 段长（描述符 TableBase 已可信，无需段起点）。
static ULONG SMeasureRvaRunForward(ULONG_PTR TableVa, ULONG_PTR TextStart,
                                   ULONG_PTR TextEnd, ULONG_PTR End)
{
    ULONG run = 0;
    for (ULONG_PTR p = TableVa; p + 4 <= End; p += 4)
    {
        if (run >= 4096) break;              // 防病态超长扫描
        LONG ev = 0;
        if (!SSafeReadBytes(p, &ev, sizeof(ev))) break;
        ULONG uv = (ULONG)(ev >> 4);
        if (uv < TextStart || uv >= TextEnd) break;
        run++;
    }
    return run;
}

// LSTAR 反汇编快速定位：KiSystemCall64 服务分发里有
//   lea r10, [rip+disp]          ; KSERVICE_TABLE_DESCRIPTOR
//   mov r10, [r10]               ; TableBase = KiServiceTable
// 先用已知 syscall 校准（老版本/真实导出），再按描述符结构校验兜底：
// 服务数 + 长连续代码 RVA 段 + 非页对齐规律，直接得到表基址。
static BOOLEAN SFindServiceTableByLstar(ULONG KnownSyscall, ULONG_PTR KnownAddress,
                                        ULONG_PTR Mz, PULONG_PTR OutTable,
                                        PBOOLEAN OutIs4)
{
    ULONG_PTR ki = __readmsr(0xC0000082);
    if (ki == 0 || ki < 0xFFFF800000000000ULL) return FALSE;
    NpDebugPrint("[syscall] lstar-scan: ki=%p known=%p sc=%lu mz=%p\n",
                 (PVOID)ki, (PVOID)KnownAddress, KnownSyscall, (PVOID)Mz);

    ULONG_PTR textStart = 0, textEnd = 0;
    BOOLEAN hasText = (Mz != 0) && SGetExecutableRange(Mz, &textStart, &textEnd);
    if (!hasText && Mz != 0)
    {
        // 可执行段解析失败（目标机差异）时退回合理 RVA 边界：
        // 条目 ≥0x1000 且 < SizeOfImage 即视为合法表项。
        LONG pe = 0;
        ULONG sizeOfImage = 0;
        if (SSafeReadBytes(Mz + 0x3C, &pe, sizeof(pe)) &&
            pe > 0 && pe <= 0x1000 &&
            SSafeReadBytes(Mz + pe + 0x38, &sizeOfImage, sizeof(sizeOfImage)) &&
            sizeOfImage >= 0x100000 && sizeOfImage <= 0x10000000)
        {
            textStart = 0x1000;
            textEnd = sizeOfImage;
        }
        else
        {
            // SizeOfImage 读不到时用宽边界（真实表项 RVA 仅数 MB）。
            textStart = 0x1000;
            textEnd = 0x20000000ULL;
        }
        hasText = TRUE;
    }
    NpDebugPrint("[syscall] lstar-scan: text=%p-%p hasText=%d\n",
                 (PVOID)textStart, (PVOID)textEnd, hasText ? 1 : 0);
    ULONG_PTR endBound = Mz ? Mz + 0x10000000ULL : 0;
    PUCHAR code = (PUCHAR)ki;
    ULONG_PTR bestTable = 0;
    ULONG bestRun = 0;
    ULONG leaCount = 0;

    for (ULONG i = 0; i + 7 <= 0x1000; i++)
    {
        if ((code[i] != 0x48 && code[i] != 0x4C) || code[i + 1] != 0x8D)
            continue;
        UCHAR modrm = code[i + 2];
        if ((modrm & 0xC7) != 0x05) continue;      // RIP 相对
        LONG disp = *(PLONG)(code + i + 3);
        ULONG_PTR target = ki + i + 7 + disp;
        if (target < 0xFFFF800000000000ULL) continue;
        leaCount++;
        if (leaCount <= 6)
        {
            NpDebugPrint("[syscall] lstar-scan: off=0x%x target=%p\n",
                         i, (PVOID)target);
        }

        // 直接指向表（老版本 lea rXX, KiServiceTable）。
        if (target + (ULONG_PTR)KnownSyscall * 8 == KnownAddress)
        {
            *OutTable = target;
            *OutIs4 = FALSE;
            return TRUE;
        }
        if (target + (ULONG_PTR)KnownSyscall * 4 == KnownAddress)
        {
            *OutTable = target;
            *OutIs4 = TRUE;
            return TRUE;
        }

        // 指向 KSERVICE_TABLE_DESCRIPTOR：读 [desc] = TableBase。
        ULONG_PTR base = 0;
        if (!SSafeReadBytes(target, &base, sizeof(base))) continue;
        if (base < 0xFFFF800000000000ULL) continue;
        if (base + (ULONG_PTR)KnownSyscall * 4 == KnownAddress)
        {
            *OutTable = base;
            *OutIs4 = TRUE;
            return TRUE;
        }
        if (base + (ULONG_PTR)KnownSyscall * 8 == KnownAddress)
        {
            *OutTable = base;
            *OutIs4 = FALSE;
            return TRUE;
        }

        // 24H2 上 KnownAddress 可能是 Zw 包装地址，锚点对不上；
        // 改用描述符结构校验：服务数 + 长连续代码 RVA 段 + 低位多样化。
        ULONG count = 0;
        if (!SSafeReadBytes(target + 0x10, &count, sizeof(count))) continue;
        if (count < 100 || count > 2000) continue;
        if (!hasText) continue;

        ULONG run = SMeasureRvaRunForward(base, textStart, textEnd, endBound);
        ULONG lows[8];
        ULONG nLow = 0;
        BOOLEAN bad = FALSE;
        for (ULONG e = 0; e < 64; e++)
        {
            ULONG v = 0;
            if (!SSafeReadBytes(base + e * 4, &v, sizeof(v))) { bad = TRUE; break; }
            ULONG lo = (v >> 4) & 0xFFF;     // 解码后 RVA 的低位
            BOOLEAN seen = FALSE;
            for (ULONG k = 0; k < nLow; k++)
            {
                if (lows[k] == lo) { seen = TRUE; break; }
            }
            if (!seen && nLow < 8) lows[nLow++] = lo;
            if (nLow >= 4) break;                    // 足够多样
        }
        NpDebugPrint("[syscall] lstar-scan: desc=%p base=%p count=%lu "
                     "run=%lu lows=%lu\n",
                     (PVOID)target, (PVOID)base, count, run, nLow);
        if (run < 128) continue;
        // 页对齐伪表（0x200000/0x200001/...）低位只有 0/1；
        // 真实 KiServiceTable 前 64 项低位应明显多样。
        if (bad || nLow < 4) continue;               // 太规律 → 伪表

        if (run > bestRun) { bestRun = run; bestTable = base; }
    }

    if (bestTable != 0)
    {
        *OutTable = bestTable;
        *OutIs4 = TRUE;
        return TRUE;
    }
    NpDebugPrint("[syscall] lstar-scan: no table (lea=%lu)\n", leaCount);
    return FALSE;
}

ULONG_PTR NpSyscallFindServiceTable(PULONG_PTR OutModuleBase, BOOLEAN *OutIs4B) {
    if (OutModuleBase) *OutModuleBase = 0;
    if (OutIs4B) *OutIs4B = FALSE;

    if (g_ServiceCacheValid)
    {
        if (OutModuleBase) *OutModuleBase = g_ServiceMb;
        if (OutIs4B) *OutIs4B = g_ServiceIs4;
        return g_ServiceTable;
    }

    // 锚点只走导出表/Zw 别名，避免经 SSDT 兜底形成递归。
    PVOID qip = NpSyscallResolveAddress("NtQueryInformationProcess");
    if (qip == nullptr) qip = NpSyscallResolveAddress("ZwQueryInformationProcess");
    ULONG qipSc = NpSyscallExtractNumber("NtQueryInformationProcess");
    PVOID qsi = NpSyscallResolveAddress("NtQuerySystemInformation");
    if (qsi == nullptr) qsi = NpSyscallResolveAddress("ZwQuerySystemInformation");
    ULONG qsiSc = NpSyscallExtractNumber("NtQuerySystemInformation");
    PVOID susp = NpSyscallResolveAddress("ZwSuspendThread");
    if (susp == nullptr) susp = NpSyscallResolveAddress("NtSuspendThread");
    ULONG suspSc = NpSyscallExtractNumber("NtSuspendThread");
    PVOID resm = NpSyscallResolveAddress("ZwResumeThread");
    if (resm == nullptr) resm = NpSyscallResolveAddress("NtResumeThread");
    ULONG resmSc = NpSyscallExtractNumber("NtResumeThread");
    if (qip == nullptr || qipSc == 0) return 0;
    NpDebugPrint("[syscall] find: qip=%p sc=%lu\n", qip, qipSc);

    //
    // 1. 从 QIP 地址向下 64KB 对齐找有效 PE32+ 映像（ntoskrnl）。
    //
    ULONG_PTR mz = (ULONG_PTR)SGetModuleBaseFromList(L"ntoskrnl.exe");
    if (mz == 0 || !SValidateImage(mz, (ULONG_PTR)qip))
    {
        mz = 0;
        for (ULONG_PTR a = (ULONG_PTR)qip & ~(ULONG_PTR)0xFFFF;
             a > 0xFFFF800000000000ull && a > ((ULONG_PTR)qip - 0x10000000ull);
             a -= 0x10000) {
            USHORT magic = 0;
            if (!SSafeReadBytes(a, &magic, sizeof(magic)) || magic != 0x5A4D) continue;
            if (SValidateImage(a, (ULONG_PTR)qip)) { mz = a; break; }
            // 诊断：MZ 命中但校验失败，打印 PE 字段定位失败原因。
            LONG pe = 0; ULONG sig2 = 0; USHORT om = 0; ULONG soi = 0;
            SSafeReadBytes(a + 0x3C, &pe, sizeof(pe));
            if (pe > 0 && pe <= 0x1000)
            {
                SSafeReadBytes(a + pe, &sig2, sizeof(sig2));
                SSafeReadBytes(a + pe + 0x18, &om, sizeof(om));
                SSafeReadBytes(a + pe + 0x38, &soi, sizeof(soi));
            }
            NpDebugPrint("[syscall] find: MZ@%p validate fail pe=0x%x "
                         "sig=0x%x opt=0x%x soi=0x%x\n",
                         (PVOID)a, pe, sig2, om, soi);
        }
    }
    NpDebugPrint("[syscall] find: mz=%p\n", (PVOID)mz);

    //
    // 2. 快速路径：LSTAR 反汇编直接读服务描述符 → KiServiceTable，
    //    避免对整份 ntoskrnl 做慢速扫描（嵌套虚拟化下会卡死 GUI）。
    //
    ULONG_PTR fastTable = 0;
    BOOLEAN fastIs4 = FALSE;
    if (SFindServiceTableByLstar(qipSc, (ULONG_PTR)qip, mz,
                                 &fastTable, &fastIs4))
    {
        NpDebugPrint("[syscall] find: fast path table=%p is4=%d\n",
                     (PVOID)fastTable, fastIs4 ? 1 : 0);
        if (!fastIs4 || mz != 0)
        {
            g_ServiceTable = fastTable;
            g_ServiceMb = fastIs4 ? mz : 0;
            g_ServiceIs4 = fastIs4;
            g_ServiceCacheValid = TRUE;
            if (OutModuleBase) *OutModuleBase = g_ServiceMb;
            if (OutIs4B) *OutIs4B = fastIs4;
            NpHvLogPrint("[syscall] service table via LSTAR fast path = 0x%p "
                         "(4B=%d)\n", (PVOID)fastTable, fastIs4 ? 1 : 0);
            return fastTable;
        }
    }
    if (mz == 0) return 0;

    // 快速路径失败直接返回：不再走全镜像扫描兜底，防止嵌套虚拟化下
    // 调用线程（GUI/加载）长时间卡死。宁可功能降级，也不阻塞界面。
    NpDebugPrint("[syscall] find: fast path failed, skip slow scan\n");
    return 0;

    LONG e_lfanew = 0;
    ULONG sizeOfImage = 0;
    if (!SSafeReadBytes(mz + 0x3C, &e_lfanew, sizeof(e_lfanew)) ||
        e_lfanew <= 0 || e_lfanew > 0x1000 ||
        !SSafeReadBytes(mz + e_lfanew + 0x50, &sizeOfImage, sizeof(sizeOfImage)))
        return 0;
    ULONG_PTR end = mz + sizeOfImage;
    // 24H2 的 Nt*/Zw* 导出可能是哨兵值；锚点必须真实落在映像内，
    // 否则双锚点匹配会永远失败（或误判），SSDT 定位直接放弃。
    if ((ULONG_PTR)qip < mz || (ULONG_PTR)qip >= end)
    {
        return 0;
    }
    BOOLEAN hasQsi = (qsi != nullptr && qsiSc != 0 &&
                      (ULONG_PTR)qsi >= mz && (ULONG_PTR)qsi < end);
    BOOLEAN hasSusp = (susp != nullptr && suspSc != 0 &&
                       (ULONG_PTR)susp >= mz && (ULONG_PTR)susp < end);
    BOOLEAN hasResm = (resm != nullptr && resmSc != 0 &&
                       (ULONG_PTR)resm >= mz && (ULONG_PTR)resm < end);
    // 4KB 页缓冲不落内核栈（_chkstk 栈探测蓝屏防护）。
    UCHAR* page = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'ySNp');
    if (page == nullptr) return 0;

    //
    // 3a. 8B 绝对地址表（老版本）。
    //
    if (hasQsi) {
        ULONG maxOff = PAGE_SIZE;
        if (hasSusp && (ULONG_PTR)suspSc * 8 + 8 > maxOff)
            maxOff = (ULONG_PTR)suspSc * 8 + 8;
        if (hasResm && (ULONG_PTR)resmSc * 8 + 8 > maxOff)
            maxOff = (ULONG_PTR)resmSc * 8 + 8;
        if ((ULONG_PTR)qsiSc * 8 + 8 < maxOff) maxOff = (ULONG)qsiSc * 8 + 8;
        if ((ULONG_PTR)qipSc * 8 + 8 > maxOff) maxOff = (ULONG)qipSc * 8 + 8;
        for (ULONG_PTR pg = mz; pg < end; pg += PAGE_SIZE) {
            if (!SSafeReadBytes(pg, page, PAGE_SIZE)) continue;
            ULONG limit = PAGE_SIZE - maxOff;
            for (ULONG off = 0; off < limit; off += 8) {
                ULONG_PTR v = *(PULONG_PTR)(page + off + qipSc * 8);
                if (v != (ULONG_PTR)qip) continue;
                v = *(PULONG_PTR)(page + off + qsiSc * 8);
                if (v != (ULONG_PTR)qsi) continue;
                if (hasSusp &&
                    *(PULONG_PTR)(page + off + suspSc * 8) != (ULONG_PTR)susp)
                    continue;
                if (hasResm &&
                    *(PULONG_PTR)(page + off + resmSc * 8) != (ULONG_PTR)resm)
                    continue;
                g_ServiceTable = pg + off;
                g_ServiceMb = mz;
                g_ServiceIs4 = FALSE;
                g_ServiceCacheValid = TRUE;
                ExFreePoolWithTag(page, 'ySNp');
                if (OutModuleBase) *OutModuleBase = mz;
                if (OutIs4B) *OutIs4B = FALSE;
                return pg + off;
            }
        }
    }

    //
    // 3b. 4B RVA 表 + 表特征验证（Win10 1903+ / Win11）。
    //
    {
        ULONG maxOff = PAGE_SIZE;
        if (hasSusp && (ULONG_PTR)suspSc * 4 + 4 > maxOff)
            maxOff = (ULONG_PTR)suspSc * 4 + 4;
        if (hasResm && (ULONG_PTR)resmSc * 4 + 4 > maxOff)
            maxOff = (ULONG_PTR)resmSc * 4 + 4;
        if ((ULONG_PTR)qsiSc * 4 + 4 < maxOff) maxOff = (ULONG)qsiSc * 4 + 4;
        if ((ULONG_PTR)qipSc * 4 + 4 > maxOff) maxOff = (ULONG)qipSc * 4 + 4;
        ULONG_PTR textStart = 0, textEnd = 0;
        SGetExecutableRange(mz, &textStart, &textEnd);
        ULONG_PTR bestTable = 0;
        ULONG bestRun = 0;
        for (ULONG_PTR pg = mz; pg < end; pg += PAGE_SIZE) {
            if (!SSafeReadBytes(pg, page, PAGE_SIZE)) continue;
            ULONG limit = PAGE_SIZE - maxOff;
            for (ULONG off = 0; off < limit; off += 4) {
                LONG o1 = *(PLONG)(page + off + qipSc * 4);
                BOOLEAN anchor;
                anchor = ((ULONG_PTR)(mz + (LONG64)o1) == (ULONG_PTR)qip);
                if (anchor && hasQsi) {
                    LONG o2 = *(PLONG)(page + off + qsiSc * 4);
                    anchor = ((ULONG_PTR)(mz + (LONG64)o2) == (ULONG_PTR)qsi);
                }
                if (anchor && hasSusp) {
                    LONG os = *(PLONG)(page + off + suspSc * 4);
                    anchor = ((ULONG_PTR)(mz + (LONG64)os) == (ULONG_PTR)susp);
                }
                if (anchor && hasResm) {
                    LONG or_ = *(PLONG)(page + off + resmSc * 4);
                    anchor = ((ULONG_PTR)(mz + (LONG64)or_) == (ULONG_PTR)resm);
                }
                if (!anchor || textStart == 0 || textEnd == 0) continue;
                ULONG run = SMeasureRvaRun(pg + off, textStart, textEnd, mz, end);
                if (run > bestRun) { bestRun = run; bestTable = pg + off; }
            }
        }
        if (bestTable != 0 && bestRun >= 128) {
            g_ServiceTable = bestTable;
            g_ServiceMb = mz;
            g_ServiceIs4 = TRUE;
            g_ServiceCacheValid = TRUE;
            ExFreePoolWithTag(page, 'ySNp');
            if (OutModuleBase) *OutModuleBase = mz;
            if (OutIs4B) *OutIs4B = TRUE;
            return bestTable;
        }
    }
    ExFreePoolWithTag(page, 'ySNp');
    return 0;
}

PVOID NpSyscallGetRoutineByNumber(ULONG s, ULONG_PTR tb, ULONG_PTR mb, BOOLEAN is4) {
    if (tb == 0 || tb < 0xFFFF800000000000ull) return nullptr;
    UNREFERENCED_PARAMETER(mb);
    if (is4) {
        ULONG off = 0;
        if (!SSafeReadBytes(tb + (ULONG_PTR)s * 4, &off, sizeof(off))) return nullptr;
        LONG soff = (LONG)off;
        if (soff == 0) return nullptr;
        // Win10/11 表项 = (offset << 4) | flags；内核用
        //   sar r11,4; add r10,r11   → 地址 = TableBase + (entry>>4)
        // 不是镜像基址 + RVA。
        ULONG_PTR addr = tb + (soff >> 4);
        return (addr >= 0xFFFF800000000000ull) ? (PVOID)addr : nullptr;
    }
    ULONG_PTR value = 0;
    if (!SSafeReadBytes(tb + (ULONG_PTR)s * 8, &value, sizeof(value))) return nullptr;
    return (value >= 0xFFFF800000000000ull) ? (PVOID)value : nullptr;
}

PVOID NpSyscallResolveRoutineEx(const char *NtName, ULONG KnownSc, ULONG *OutSc) {
    ULONG sc = (KnownSc != 0) ? KnownSc : NpSyscallExtractNumber(NtName);
    if (OutSc) *OutSc = sc;

    // 24H2 导出表里的 Nt*/Zw* 可能是包装/syscall stub，不是 SSDT 表里的
    // 真实处理函数；转发语义必须用真实 Nt 处理函数，所以优先 SSDT。
    if (sc != 0)
    {
        ULONG_PTR mb = 0;
        BOOLEAN is4 = FALSE;
        ULONG_PTR tb = NpSyscallFindServiceTable(&mb, &is4);
        if (tb != 0)
        {
            PVOID addr = NpSyscallGetRoutineByNumber(sc, tb, mb, is4);
            if (addr != nullptr)
            {
                if (is4 && mb != 0)
                {
                    ULONG_PTR ts = 0, te = 0;
                    // 段解析失败不阻断（用 SSDT 表本身校验过即可）。
                    if (!SGetExecutableRange(mb, &ts, &te)) return addr;
                    ULONG_PTR a = (ULONG_PTR)addr;
                    if (a >= mb + ts && a < mb + te) return addr;
                }
                else
                {
                    return addr;
                }
            }
        }
    }

    // 导出表兜底（老系统/SSDT 不可用时）。
    PVOID p = NpSyscallResolveAddress(NtName);
    if (p) return p;
    if (NtName[0] == 'N' && NtName[1] == 't')
    {
        char zw[64];
        ULONG len = (ULONG)strlen(NtName);
        if (len + 1 < sizeof(zw))
        {
            zw[0] = 'Z'; zw[1] = 'w';
            RtlCopyMemory(zw + 2, NtName + 2, len - 1);
            p = NpSyscallResolveAddress(zw);
            if (p) return p;
        }
    }
    return nullptr;
}

PVOID NpSyscallResolveRoutine(const char *NtName, ULONG *OutSc) {
    return NpSyscallResolveRoutineEx(NtName, 0, OutSc);
}

static VOID SRebuildInterceptTable(void)
{
    if (!g_BaseResolved)
    {
        ULONG got = 0;
        for (ULONG i = 0; i < NP_INTERCEPT_COUNT; i++)
        {
            g_BaseNumbers[i] = NpSyscallExtractNumber(g_InterceptNames[i]);
            if (g_BaseNumbers[i] != 0) got++;
        }
        // 至少解析到号码才缓存；全 0 表示当前无 ntdll（System 上下文），
        // 留给用户进程上下文重试，避免缓存被 0 污染。
        g_BaseResolved = (got > 0);
    }
    g_InterceptNumberCount = 0;
    for (ULONG i = 0; i < NP_INTERCEPT_COUNT; i++)
    {
        ULONG sc = g_BaseNumbers[i];
        if (sc != 0) g_InterceptNumbers[g_InterceptNumberCount++] = sc;
    }
    for (ULONG i = 0; i < g_DynamicCount; i++)
    {
        ULONG sc = g_DynamicNumbers[i];
        if (sc == 0) continue;
        BOOLEAN dup = FALSE;
        for (ULONG j = 0; j < g_InterceptNumberCount; j++)
            if (g_InterceptNumbers[j] == sc) { dup = TRUE; break; }
        if (!dup && g_InterceptNumberCount < NP_INTERCEPT_MAX)
            g_InterceptNumbers[g_InterceptNumberCount++] = sc;
    }
}

NTSTATUS NpSyscallInitialize(void) {
    SResolveNtdllFromUserProcess();
    SRebuildInterceptTable();
    NpHvLogPrint("[syscall] intercept table: %lu/%u syscall numbers resolved\n",
                 g_InterceptNumberCount, (ULONG)NP_INTERCEPT_COUNT);
    return STATUS_SUCCESS;
}

NTSTATUS NpSyscallRefreshIntercepts(void)
{
    NpDebugPrint("[syscall] refresh: begin pid=%lu\n",
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    SRebuildInterceptTable();
    NpDebugPrint("[syscall] refresh: rebuilt count=%lu\n",
                 g_InterceptNumberCount);
    NpHvLogPrint("[syscall] refreshed intercept table: %lu/%u resolved\n",
                 g_InterceptNumberCount, (ULONG)NP_INTERCEPT_COUNT);
    return STATUS_SUCCESS;
}

NTSTATUS NpSyscallSetIntercept(const char *NtName, BOOLEAN Enable)
{
    ULONG sc = NpSyscallExtractNumber(NtName);
    if (sc == 0) return STATUS_NOT_FOUND;

    if (Enable)
    {
        for (ULONG i = 0; i < g_InterceptNumberCount; i++)
            if (g_InterceptNumbers[i] == sc) return STATUS_SUCCESS;
        for (ULONG i = 0; i < g_DynamicCount; i++)
            if (g_DynamicNumbers[i] == sc) return STATUS_SUCCESS;
        if (g_InterceptNumberCount >= NP_INTERCEPT_MAX)
            return STATUS_BUFFER_OVERFLOW;
        if (g_DynamicCount < ARRAYSIZE(g_DynamicNumbers))
            g_DynamicNumbers[g_DynamicCount++] = sc;
        g_InterceptNumbers[g_InterceptNumberCount++] = sc;
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < g_DynamicCount; i++)
    {
        if (g_DynamicNumbers[i] == sc)
        {
            g_DynamicNumbers[i] = g_DynamicNumbers[g_DynamicCount - 1];
            g_DynamicCount--;
            break;
        }
    }
    for (ULONG i = 0; i < g_InterceptNumberCount; i++)
    {
        if (g_InterceptNumbers[i] == sc)
        {
            g_InterceptNumbers[i] = g_InterceptNumbers[g_InterceptNumberCount - 1];
            g_InterceptNumberCount--;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS NpSyscallCopyIntercepts(PULONG Out, ULONG Cap, PULONG OutCount)
{
    if (Out == nullptr || OutCount == nullptr) return STATUS_INVALID_PARAMETER;
    if (g_InterceptNumberCount > Cap) return STATUS_BUFFER_OVERFLOW;
    RtlCopyMemory(Out, g_InterceptNumbers,
                  sizeof(ULONG) * g_InterceptNumberCount);
    *OutCount = g_InterceptNumberCount;
    return STATUS_SUCCESS;
}

void NpSyscallTeardown(void) {
    g_InterceptNumberCount = 0;
    g_DynamicCount = 0;
}

BOOLEAN NpSyscallIsIntercepted(ULONG SyscallNumber) {
    for (ULONG i = 0; i < g_InterceptNumberCount; i++) {
        if (g_InterceptNumbers[i] == SyscallNumber) return TRUE;
    }
    return FALSE;
}

NTSTATUS NpSyscallPrecheck(NPSYSCALL_PRECHECK_RESULT *Out) {
    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));
    const char *names[NPSYSCALL_PRECHECK_COUNT] = {
        "NtQueryInformationProcess",
        "NtQuerySystemInformation",
        "RtlFindExportedRoutineByName",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtDebugActiveProcess",
        "NtSetContextThread",
    };
    const BOOLEAN isSc[NPSYSCALL_PRECHECK_COUNT] = {
        TRUE, TRUE, FALSE, TRUE, TRUE, TRUE, TRUE,
    };
    Out->Count = NPSYSCALL_PRECHECK_COUNT;
    for (ULONG i = 0; i < NPSYSCALL_PRECHECK_COUNT; i++) {
        Out->Entries[i].Name = names[i];
        Out->Entries[i].IsSyscall = isSc[i];
        Out->Entries[i].Syscall = isSc[i] ? NpSyscallExtractNumber(names[i]) : 0;
        Out->Entries[i].Address = NpSyscallResolveRoutine(names[i], nullptr);
        Out->Entries[i].Resolved = (Out->Entries[i].Address != nullptr);
    }

    //
    // SSDT 表交叉校验：找到表后按 syscall 号回读 QIP/QSI 地址，
    // 与导出表解析结果比对（4B/8B 变体均覆盖）。
    //
    ULONG_PTR mb = 0;
    BOOLEAN is4 = FALSE;
    Out->ServiceTable = NpSyscallFindServiceTable(&mb, &is4);
    Out->ModuleBase = mb;
    Out->Is4B = is4;
    if (Out->ServiceTable != 0) {
        ULONG qipSc = Out->Entries[0].Syscall;
        ULONG qsiSc = Out->Entries[1].Syscall;
        PVOID qipViaTable = NpSyscallGetRoutineByNumber(qipSc, Out->ServiceTable, mb, is4);
        PVOID qsiViaTable = NpSyscallGetRoutineByNumber(qsiSc, Out->ServiceTable, mb, is4);
        Out->TableCrossChecked =
            (qipViaTable == Out->Entries[0].Address && Out->Entries[0].Address != nullptr) ||
            (qsiViaTable == Out->Entries[1].Address && Out->Entries[1].Address != nullptr);
    }

    Out->AllPassed = TRUE;
    for (ULONG i = 0; i < NPSYSCALL_PRECHECK_COUNT; i++) {
        if (Out->Entries[i].IsSyscall) {
            if (Out->Entries[i].Syscall == 0 || !Out->Entries[i].Resolved)
                Out->AllPassed = FALSE;
        } else if (!Out->Entries[i].Resolved) {
            Out->AllPassed = FALSE;
        }
    }
    return Out->AllPassed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
