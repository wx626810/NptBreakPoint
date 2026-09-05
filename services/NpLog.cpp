/*!
    @file       NpLog.cpp

    @brief      services/NpLog：分级环形日志服务。

    @details    任意 IRQL 安全的环形缓冲区写入（NpLogPrint），
                由落盘线程定期冲刷到 C:\Windows\NptHook.log，
                同时输出到内核调试器。独立成模块后，其他服务
                通过 NpLogPrint / NpLogInfo / NpLogWarn 使用。
 */
#define POOL_NX_OPTIN   1
#include "NpLog.h"
#include <ntstrsafe.h>
#include <intrin.h>
#include "NpConfig.h"

#if NPTHOOK_LOG_ENABLE


//
// 环形缓冲区（由落盘线程冲刷）
//
#define NPTHOOK_LOG_BUFFER_SIZE (64 * 1024)

static UCHAR g_LogBuffer[NPTHOOK_LOG_BUFFER_SIZE];
static volatile LONG g_LogWritePos = 0;
static KSPIN_LOCK g_LogLock;
static volatile NP_LOG_LEVEL g_LogLevel = NpLogLevelInfo;
static HANDLE g_LogFlushThreadHandle = nullptr;
static volatile BOOLEAN g_LogFlushThreadExit = FALSE;
static volatile BOOLEAN g_LogFlushThreadExited = FALSE;  // 线程已退出（高 IRQL 忙等用）

//
// ============================ 调试输出 ============================
//

#pragma prefast(push)
#pragma prefast(disable : 26826, "C-style variable arguments needed for DbgPrint.")
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NpDebugPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    // 2026-08-29: 驱动静默 —— 空化，不再输出任何 DbgPrint。
    UNREFERENCED_PARAMETER(Format);
    return;

    va_list argList;

    va_start(argList, Format);
    vDbgPrintExWithPrefix("[NpHv] ",
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_ERROR_LEVEL,
                          Format,
                          argList);
    va_end(argList);
}
#pragma prefast(pop)

/*!
    @brief      向环形日志缓冲区写入一行（任意 IRQL 安全；级别过滤）。
 */
#pragma prefast(push)
#pragma prefast(disable : 26826, "C-style variable arguments needed for logging.")
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NpLogPrint(
    _In_ NP_LOG_LEVEL Level,
    _In_z_ _Printf_format_string_ const char* Format,
    ...
    )
{
    // 2026-08-29: 驱动静默 —— 空化。不再写环形缓冲/落盘，也不输出。
    // 保留函数与全部调用点，未来需要日志时删掉这三行即可恢复。
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(Format);
    return;

    char line[256];
    ULONG len;
    KIRQL oldIrql;

    if (Level > g_LogLevel)
    {
        return;
    }

    va_list argList;
    va_start(argList, Format);
    RtlStringCbVPrintfA(line, sizeof(line), Format, argList);
    va_end(argList);

    len = static_cast<ULONG>(strlen(line));
    if (len == 0)
    {
        return;
    }

    KeAcquireSpinLock(&g_LogLock, &oldIrql);
    if (g_LogWritePos + len + 1 >= NPTHOOK_LOG_BUFFER_SIZE)
    {
        g_LogWritePos = 0;      // 环形：丢弃旧数据
    }
    RtlCopyMemory(g_LogBuffer + g_LogWritePos, line, len);
    g_LogWritePos += len;
    g_LogBuffer[g_LogWritePos] = '\n';
    g_LogWritePos += 1;
    KeReleaseSpinLock(&g_LogLock, oldIrql);
}
#pragma prefast(pop)

/*!
    @brief      兼容旧 API：等价于 NpLogPrint(NpLogLevelInfo, ...)。
 */
#pragma prefast(push)
#pragma prefast(disable : 26826, "C-style variable arguments needed for logging.")
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NpHvLogPrint(
    _In_z_ _Printf_format_string_ const char* Format,
    ...
    )
{
    // Fix 0xA at DISPATCH: RtlStringCbVPrintfA -> wctomb_s -> RtlpIsUtf8Process touches PEB (paged) at IRQL 2
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return;
    }
    char line[256];
    ULONG len;
    KIRQL oldIrql;

    va_list argList;
    va_start(argList, Format);
    RtlStringCbVPrintfA(line, sizeof(line), Format, argList);
    va_end(argList);

    len = static_cast<ULONG>(strlen(line));
    if (len == 0)
    {
        return;
    }

    KeAcquireSpinLock(&g_LogLock, &oldIrql);
    if (g_LogWritePos + len + 1 >= NPTHOOK_LOG_BUFFER_SIZE)
    {
        g_LogWritePos = 0;
    }
    RtlCopyMemory(g_LogBuffer + g_LogWritePos, line, len);
    g_LogWritePos += len;
    g_LogBuffer[g_LogWritePos] = '\n';
    g_LogWritePos += 1;
    KeReleaseSpinLock(&g_LogLock, oldIrql);
}
#pragma prefast(pop)

/*!
    @brief      日志落盘线程：定期把环形缓冲区写到文件，并输出到调试器。
 */
static
VOID
NpLogFlushThread(
    _In_ PVOID StartContext
    )
{
    UNREFERENCED_PARAMETER(StartContext);
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle;
    KIRQL oldIrql;
    LARGE_INTEGER interval;
    PVOID buffer;
    LONG pos;

    fileHandle = nullptr;
    buffer = nullptr;
    interval.QuadPart = -50 * 10000;     // 50ms（蓝屏前丢尾窗口尽量小）

    RtlInitUnicodeString(&fileName, NP_LOG_FILE_PATH);
    InitializeObjectAttributes(&objectAttributes,
                               &fileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr,
                               nullptr);

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, NPTHOOK_LOG_BUFFER_SIZE, 'goLt');
    if (buffer == nullptr)
    {
        NpDebugPrint("Failed to allocate log buffer.\n");
        return;
    }

    for (;;)
    {
        if (g_LogFlushThreadExit)
        {
            break;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (g_LogFlushThreadExit)
        {
            break;
        }

        //
        // 快照并清空环形缓冲区。
        //
        KeAcquireSpinLock(&g_LogLock, &oldIrql);
        pos = g_LogWritePos;
        if (pos > 0)
        {
            RtlCopyMemory(buffer, g_LogBuffer, pos);
            g_LogWritePos = 0;
        }
        KeReleaseSpinLock(&g_LogLock, oldIrql);

        if (pos <= 0)
        {
            continue;
        }

        //
        // 打开文件（首次）。
        //
        if (fileHandle == nullptr)
        {
            NTSTATUS status = ZwCreateFile(&fileHandle,
                                           GENERIC_WRITE,
                                           &objectAttributes,
                                           &ioStatus,
                                           nullptr,
                                           FILE_ATTRIBUTE_NORMAL,
                                           FILE_SHARE_READ,
                                           FILE_OVERWRITE_IF,
                                           FILE_SYNCHRONOUS_IO_NONALERT,
                                           nullptr,
                                           0);
            if (!NT_SUCCESS(status))
            {
                NpDebugPrint("Failed to open log file: 0x%08x\n", status);
                fileHandle = nullptr;
            }
        }

        if (fileHandle != nullptr)
        {
            NTSTATUS status = ZwWriteFile(fileHandle,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          &ioStatus,
                                          buffer,
                                          pos,
                                          nullptr,
                                          nullptr);
            if (!NT_SUCCESS(status))
            {
                NpDebugPrint("Failed to write log file: 0x%08x\n", status);
            }
        }

        //
        // 同时输出到内核调试器。
        //
        static_cast<PCHAR>(buffer)[pos] = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "%s",
                   static_cast<PCHAR>(buffer));
    }

    //
    // 线程终止路径：驱动卸载时设置 g_LogFlushThreadExit 后等待退出。
    //
    ExFreePoolWithTag(buffer, 'goLt');
    g_LogFlushThreadExited = TRUE;      // 供高 IRQL 忙等轮询确认退出
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*!
    @brief      初始化日志服务：初始化锁并启动落盘线程。
 */
#else // !NPTHOOK_LOG_ENABLE

_Use_decl_annotations_
NTSTATUS
NpLogInitialize(
    VOID)
{
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
NpLogTeardown(
    VOID)
{
}

_Use_decl_annotations_
VOID
NpLogSetLevel(
    NP_LOG_LEVEL Level)
{
    UNREFERENCED_PARAMETER(Level);
}

#endif // NPTHOOK_LOG_ENABLE

#if NPTHOOK_LOG_ENABLE
_Use_decl_annotations_
NTSTATUS
NpLogInitialize(
    VOID)
{
    KeInitializeSpinLock(&g_LogLock);
    return PsCreateSystemThread(&g_LogFlushThreadHandle,
                                THREAD_ALL_ACCESS,
                                nullptr,
                                nullptr,
                                nullptr,
                                NpLogFlushThread,
                                nullptr);
}

/*!
    @brief      停止日志服务：请求线程退出并等待。
 */
_Use_decl_annotations_
VOID
NpLogTeardown(
    VOID)
{
    KIRQL irql;

    g_LogFlushThreadExit = TRUE;
    if (g_LogFlushThreadHandle != nullptr)
    {
        //
        // 防御：KeWaitForSingleObject 必须 PASSIVE_LEVEL（与复位线程同款
        // 0xA 蓝屏防护）；高 IRQL 时忙等轮询 + 打日志定位泄漏点。
        //
        irql = KeGetCurrentIrql();
        if (irql >= DISPATCH_LEVEL)
        {
            NpHvLogPrint("[log] teardown: IRQL=%u >= DISPATCH, polling\n", irql);
            for (ULONG i = 0; i < 40000 && !g_LogFlushThreadExited; i++)
            {
                KeStallExecutionProcessor(100);
            }
            if (!g_LogFlushThreadExited)
            {
                NpHvLogPrint("[log] WARNING: flush thread did not exit in 4s, handle leaked (irql=%u)\n", irql);
                return;
            }
        }
        else
        {
            ZwWaitForSingleObject(g_LogFlushThreadHandle, FALSE, NULL);
        }
        ZwClose(g_LogFlushThreadHandle);
        g_LogFlushThreadHandle = nullptr;
    }
}

_Use_decl_annotations_
VOID
NpLogSetLevel(
    NP_LOG_LEVEL Level)
{
    g_LogLevel = Level;
}

#endif // NPTHOOK_LOG_ENABLE
