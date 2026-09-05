/*!
    @file       NpLog.h

    @brief      services/NpLog 模块接口：分级环形日志 + 落盘线程。
 */
#pragma once

#include <ntifs.h>

//
// 日志级别。默认只记录 <= 配置级别的行（NpLogSetLevel 可运行时调整）。
//
typedef enum _NP_LOG_LEVEL
{
    NpLogLevelError = 0,
    NpLogLevelWarning = 1,
    NpLogLevelInfo = 2,
    NpLogLevelTrace = 3
} NP_LOG_LEVEL;

#include "NpConfig.h"

#if NPTHOOK_LOG_ENABLE
extern "C" {

// 初始化日志服务（分配缓冲、启动落盘线程）。
NTSTATUS NpLogInitialize(
    VOID);

// 停止落盘线程并释放资源（卸载路径）。
VOID NpLogTeardown(
    VOID);

// 运行时调整级别。
VOID NpLogSetLevel(
    _In_ NP_LOG_LEVEL Level);

// 环形日志（任意 IRQL 安全；由落盘线程定期冲刷到文件）。
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID NpLogPrint(
    _In_ NP_LOG_LEVEL Level,
    _In_z_ _Printf_format_string_ const char* Format,
    ...);

// 调试器输出（DbgPrint 前缀封装）。
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID NpDebugPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...);

// 兼容旧 API：等价于 NpLogPrint(NpLogLevelInfo, ...)。
// 旧模块（NpHook.cpp 等）暂未迁移时可继续调用。
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID NpHvLogPrint(
    _In_z_ _Printf_format_string_ const char* Format,
    ...);

} // extern "C"

#else
// 日志关闭：全部变空操作（含格式化参数求值都被剔除）
extern "C" {
NTSTATUS NpLogInitialize(VOID);
VOID NpLogTeardown(VOID);
VOID NpLogSetLevel(_In_ NP_LOG_LEVEL Level);
} // extern "C"
#define NpLogPrint(Level, Format, ...)   ((void)0)
#define NpDebugPrint(Format, ...)        ((void)0)
#define NpHvLogPrint(Format, ...)        ((void)0)
#endif // NPTHOOK_LOG_ENABLE

// 便捷宏（保持与旧 NpHvLogPrint 的调用习惯兼容）
#define NpLogInfo(Format, ...)  NpLogPrint(NpLogLevelInfo, Format, ##__VA_ARGS__)
#define NpLogWarn(Format, ...)  NpLogPrint(NpLogLevelWarning, Format, ##__VA_ARGS__)
#define NpLogError(Format, ...) NpLogPrint(NpLogLevelError, Format, ##__VA_ARGS__)
