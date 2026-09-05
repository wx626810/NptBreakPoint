/*!
    @file       NpIoctl.h

    @brief      R3（用户态）↔ R0（驱动）通信协议定义。

    @details    本头文件被内核侧与用户侧共享：
                - 内核侧：services/NpDevIoctl.cpp（include "NpIoctl.h"）
                - 用户侧：NpHvCtl/（直接 include 本文件）
                协议版本号用于双向校验，防止新旧驱动/客户端不匹配。

    @note       隐蔽性演进（当前为标准 \Device 接口）：
                1. 设备对象伪装（更名/隐藏符号链接）
                2. IOCTL 请求体加密 + 随机 cookie 防重放
                3. 去掉设备面，改用"影子通道"（借系统服务 Hook 传参）
                4. 全量走 VMMCALL 管理通道（R3→R0→HV 单链路）
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// ============================ 设备与版本 ============================
//

// 注意：反斜杠必须双写。\D/\N 是未定义转义，编译器会静默丢弃反斜杠，
// 得到 "DeviceNpHv" → IoCreateDevice 返回 STATUS_OBJECT_PATH_SYNTAX_BAD。
#define NPHV_DEVICE_NAME         L"\\Device\\NpHv"
#define NPHV_DOS_DEVICE_NAME     L"\\DosDevices\\NpHv"

#define NPHV_PROTOCOL_VERSION    1

//
// ============================ IOCTL 码 ============================
//
// METHOD_BUFFERED：输入=OutputBuffer 前段，输出=OutputBuffer 后段。
// 内核侧用 wdm 的 CTL_CODE；用户侧用 winioctl.h 的 CTL_CODE（同宏）。
//

#define NPHV_IOCTL_BASE          0x8000

#define IOCTL_NPHV_QUERY_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_INSTALL_HOOK   CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_UNINSTALL_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_UNINSTALL_ALL  CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DEVIRTUALIZE   CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_VMCALL         CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// ============== NPT 无痕断点 / NPT 监视 / 无痕读写（NpBreakPoint） ==============
//
#define IOCTL_NPHV_INSTALL_BREAKPOINT   CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_UNINSTALL_BREAKPOINT CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_LIST_BREAKPOINTS     CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_CONTINUE_BREAKPOINT  CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_INSTALL_MONITOR      CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_UNINSTALL_MONITOR    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_READ_MEMORY          CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DRPROBE             CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DRSTATE             CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DEBUG_HIDE          CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DEBUG_PROTECT       CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 16, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DEBUG_MODE          CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 17, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ============================ Hook 动作类型 ============================
//
// R3 通过动作类型描述"把目标函数变成什么样"。
// 内置动作由 R0 模板实现；CustomCode 允许 R3 传入位置无关的机器码
// （完全信任 R3：只要拿到设备句柄即可注入内核执行代码）。
//

typedef enum _NPHV_HOOK_ACTION
{
    NpHookActionLogOnly = 0,    // 记录调用（参数/返回值）并放行
    NpHookActionReturnValue,    // 拦截：返回指定值（Rax = ReturnValue）
    NpHookActionPassThrough,    // 完全放行（仅触发统计）
    NpHookActionCustomCode,     // 执行 R3 传入的机器码（见回调约定）
    NpHookActionMax
} NPHV_HOOK_ACTION;

//
// 自定义代码回调约定（R3 机器码必须遵守）：
//   BOOLEAN __fastcall Callback(PHOOK_CALL_CONTEXT Ctx)
//     rcx = Ctx 指针；Ctx 布局见 NpTypes.h 的 HOOK_CALL_CONTEXT
//     （+0x00 OriginalFunction, +0x08 ReturnAddress, +0x10 Rax, ...）
//     返回 al：0=放行（执行原函数），1=拦截（不执行，返回 Ctx->Rax）
//   代码必须是位置无关机器码（无重定位、无绝对地址引用）。
//
#define NPHV_MAX_CODE_SIZE      512

//
// ============================ 请求 / 响应结构 ============================
//

// 查询状态
typedef struct _NPHV_STATUS_RESPONSE
{
    uint32_t Version;               // NPHV_PROTOCOL_VERSION
    uint32_t HypervisorRunning;     // 0/1
    uint32_t ProcessorCount;
    uint32_t ActiveHookCount;
    uint32_t RetiredHookCount;
    uint32_t Flags;                 // 位标志（见下）
} NPHV_STATUS_RESPONSE, *PNPHV_STATUS_RESPONSE;

// STATUS_RESPONSE.Flags 位定义
#define NPHV_FLAG_SELF_HIDE         0x00000001  // 驱动已从模块列表隐藏

// 安装 Hook
typedef struct _NPHV_INSTALL_HOOK_REQUEST
{
    uint32_t Version;
    uint32_t Action;                // NPHV_HOOK_ACTION
    uint64_t TargetAddress;         // 直接内核地址（TargetName 为空时使用）
    uint64_t ReturnValue;           // Action=ReturnValue 时拦截返回的值
    char TargetName[64];            // 导出内核函数名（如 "NtQuerySystemInformation"），优先使用
    uint32_t CodeSize;              // Action=CustomCode 时的有效代码长度（<= NPHV_MAX_CODE_SIZE）
    uint32_t Reserved;
    uint8_t CodeBytes[NPHV_MAX_CODE_SIZE];  // 内嵌位置无关机器码
} NPHV_INSTALL_HOOK_REQUEST, *PNPHV_INSTALL_HOOK_REQUEST;

typedef struct _NPHV_INSTALL_HOOK_RESPONSE
{
    uint32_t HookId;                // 后续卸载/操作使用
    uint32_t Status;                // NTSTATUS
} NPHV_INSTALL_HOOK_RESPONSE, *PNPHV_INSTALL_HOOK_RESPONSE;

// 卸载 Hook
typedef struct _NPHV_UNINSTALL_HOOK_REQUEST
{
    uint32_t Version;
    uint32_t HookId;
} NPHV_UNINSTALL_HOOK_REQUEST, *PNPHV_UNINSTALL_HOOK_REQUEST;

typedef struct _NPHV_UNINSTALL_HOOK_RESPONSE
{
    uint32_t Status;                // NTSTATUS
} NPHV_UNINSTALL_HOOK_RESPONSE, *PNPHV_UNINSTALL_HOOK_RESPONSE;

// 通用 vmmcall 透传（预留：未来 R3 → HV 特权操作）
typedef struct _NPHV_VMCALL_REQUEST
{
    uint32_t Version;
    uint32_t FunctionCode;
    uint64_t InData[4];
} NPHV_VMCALL_REQUEST, *PNPHV_VMCALL_REQUEST;

typedef struct _NPHV_VMCALL_RESPONSE
{
    uint32_t Status;                // NTSTATUS
    uint64_t OutData[4];
} NPHV_VMCALL_RESPONSE, *PNPHV_VMCALL_RESPONSE;

// 统一请求头（BUFFERED 模式下：Input 在前，Output 在后）
#define NPHV_IOCTL_INPUT_SIZE(_Struct)    (sizeof(_Struct))

//
// ============================ NPT 无痕断点 ============================
//
// 断点不修改任何 Guest 内存字节：读目标地址永远是原始指令；
// 只有 CPU 取指时才经影子页执行 INT3，产生 #BP VMEXIT 由 VMM 接管。
// AMD 语义：#BP 被拦截时 VMCB.Rip 指向 INT3 所在地址（与 Intel 的
// rip-1 约定不同，见 NpSvm.h / NpBreakPoint.cpp）。
//

// 断点行为标志
#define NPHV_BP_FLAG_HALT      0x00000001  // 暂停模式：命中后钉住该线程（需 CONTINUE 放行）
#define NPHV_BP_FLAG_ONESHOT   0x00000002  // 单次模式：命中后自动解除（不重新布点）
#define NPHV_BP_FLAG_DEBUGGER  0x00000004  // 调试器透传：命中后注入 #BP 给 Guest 调试体系
                                           // （X64DBG 原生收到断点事件），影子页放行原指令
// 默认（无标志）= 自动单步模式：命中记录现场 → 单步执行原指令 → 重新布点

// 安装断点
typedef struct _NPHV_INSTALL_BREAKPOINT_REQUEST
{
    uint32_t Version;
    uint32_t Flags;                 // NPHV_BP_FLAG_*
    uint64_t TargetAddress;         // 直接地址（TargetName 为空时使用）
    char TargetName[64];            // 导出内核函数名（可选，优先）
} NPHV_INSTALL_BREAKPOINT_REQUEST, *PNPHV_INSTALL_BREAKPOINT_REQUEST;

typedef struct _NPHV_INSTALL_BREAKPOINT_RESPONSE
{
    uint32_t BpId;                  // 断点句柄（卸载/继续用）
    uint32_t Status;                // NTSTATUS
} NPHV_INSTALL_BREAKPOINT_RESPONSE, *PNPHV_INSTALL_BREAKPOINT_RESPONSE;

// 卸载断点
typedef struct _NPHV_UNINSTALL_BREAKPOINT_REQUEST
{
    uint32_t Version;
    uint32_t BpId;
} NPHV_UNINSTALL_BREAKPOINT_REQUEST, *PNPHV_UNINSTALL_BREAKPOINT_REQUEST;

// 断点信息条目（查询列表用）
typedef struct _NPHV_BREAKPOINT_INFO_ENTRY
{
    uint32_t BpId;
    uint32_t Flags;
    uint32_t Active;                // 0/1
    uint32_t Halted;                // 0/1（暂停模式且正在钉住）
    uint64_t Address;               // 断点 VA
    uint64_t HitCount;              // 累计命中次数
    uint64_t LastHitCr3;            // 最近一次命中的 CR3（进程标识）
    uint64_t LastHitRip;            // 最近一次命中时（INT3 执行后）的 RIP
    uint32_t LastHitCpu;            // 最近一次命中的 CPU
    uint32_t Reserved;
} NPHV_BREAKPOINT_INFO_ENTRY, *PNPHV_BREAKPOINT_INFO_ENTRY;

#define NPHV_MAX_BREAKPOINTS      64
#define NPHV_MAX_MONITORS         64

// 查询断点列表
typedef struct _NPHV_LIST_BREAKPOINTS_RESPONSE
{
    uint32_t Count;                 // 返回的条目数
    uint32_t Total;                 // 当前活动断点总数
    NPHV_BREAKPOINT_INFO_ENTRY Entries[NPHV_MAX_BREAKPOINTS];
} NPHV_LIST_BREAKPOINTS_RESPONSE, *PNPHV_LIST_BREAKPOINTS_RESPONSE;

// 继续被暂停的断点（HALT 模式）
typedef struct _NPHV_CONTINUE_BREAKPOINT_REQUEST
{
    uint32_t Version;
    uint32_t BpId;                  // 0 = 全部被暂停的断点
} NPHV_CONTINUE_BREAKPOINT_REQUEST, *PNPHV_CONTINUE_BREAKPOINT_REQUEST;

//
// ============================ NPT 监视（模拟硬件断点） ============================
//
// 撤销目标页的 R/W 权限，数据访问触发 #NPF → VMM 记录现场 → 恢复权限 →
// 单步（RFLAGS.TF + #DB 拦截）→ 重新收紧。不占用 DR0-DR7，数量不受限。
// AMD 限制（NPT 无 execute-only）：读监视（清 R）会同时拦截取指。
//

#define NPHV_MON_ACCESS_READ    0x00000001
#define NPHV_MON_ACCESS_WRITE   0x00000002

typedef struct _NPHV_INSTALL_MONITOR_REQUEST
{
    uint32_t Version;
    uint32_t AccessType;            // NPHV_MON_ACCESS_READ | WRITE
    uint64_t TargetAddress;         // 目标页内任意地址（按页监视）
    char TargetName[64];            // 导出内核函数名（可选，优先）
} NPHV_INSTALL_MONITOR_REQUEST, *PNPHV_INSTALL_MONITOR_REQUEST;

typedef struct _NPHV_INSTALL_MONITOR_RESPONSE
{
    uint32_t MonitorId;
    uint32_t Status;                // NTSTATUS
} NPHV_INSTALL_MONITOR_RESPONSE, *PNPHV_INSTALL_MONITOR_RESPONSE;

typedef struct _NPHV_UNINSTALL_MONITOR_REQUEST
{
    uint32_t Version;
    uint32_t MonitorId;
} NPHV_UNINSTALL_MONITOR_REQUEST, *PNPHV_UNINSTALL_MONITOR_REQUEST;

//
// ============================ 无痕读写（NPT 二阶段翻译） ============================
//
// 遍历 Guest 页表（GVA→GPA）+ NPT（GPA→HPA）后直接读物理内存，
// 不经过 Windows 内存管理接口（不被 NtReadVirtualMemory 等钩子察觉）。
// 目标数据页必须驻留物理内存（分页页返回 STATUS_NOT_FOUND）。
//

#define NPHV_MAX_MEMORY_IO       0x1000   // 单次读写上限 4KB（一页）

typedef struct _NPHV_READ_MEMORY_REQUEST
{
    uint32_t Version;
    uint32_t ProcessId;             // 目标进程（0 = System）
    uint64_t VirtualAddress;        // 目标 GVA
    uint32_t Size;                  // 0 < Size <= NPHV_MAX_MEMORY_IO
    uint32_t Reserved;
} NPHV_READ_MEMORY_REQUEST, *PNPHV_READ_MEMORY_REQUEST;

typedef struct _NPHV_READ_MEMORY_RESPONSE
{
    uint32_t Status;                // NTSTATUS（读取结果）
    uint32_t BytesRead;
    uint8_t Buffer[NPHV_MAX_MEMORY_IO];
} NPHV_READ_MEMORY_RESPONSE, *PNPHV_READ_MEMORY_RESPONSE;

//
// ============================ DR 硬件断点虚拟化（drprobe） ============================
//
// 开启后 SVM 拦截 Guest 对 DR0-3/DR6/DR7 的读写：
// - 写：HV 记录"假 DR"（调试器设的硬件断点地址/条件可见）；
// - 读：HV 回显假 DR（调试器以为断点已生效）。
// 调试器（X64DBG 等）设置的硬件断点由此被探测，可再由 R3 侧转发为
// NPT 无痕断点/监视（见 docs/调试器适配方案.md）。
// 默认关闭（零性能开销）；调试会话期间开启。
//

// 开启/关闭 DR 探测
typedef struct _NPHV_DRPROBE_REQUEST
{
    uint32_t Version;
    uint32_t Enable;                // 0=关闭（恢复直通），1=开启（接管）
} NPHV_DRPROBE_REQUEST, *PNPHV_DRPROBE_REQUEST;

// 查询假 DR 状态（当前 CPU 0 的快照）
typedef struct _NPHV_DRSTATE_RESPONSE
{
    uint32_t Status;                // NTSTATUS
    uint32_t DrProbeEnabled;        // 0/1
    uint32_t PendingCount;          // 最近使能槽的断点地址数（0-4）
    uint32_t Reserved;
    uint64_t Dr0, Dr1, Dr2, Dr3;    // 假 DR（Guest 最后写入的值）
    uint64_t Dr6, Dr7;
    uint64_t PendingAddresses[4];   // DR7 使能槽对应的断点地址
    uint64_t PendingTypes[4];       // 对应槽的访问类型（见下）
} NPHV_DRSTATE_RESPONSE, *PNPHV_DRSTATE_RESPONSE;

// DR7.RW 编码（PendingTypes）
#define NPHV_DR_RW_EXECUTE      0x00    // 执行断点
#define NPHV_DR_RW_WRITE        0x01    // 写断点
#define NPHV_DR_RW_IO           0x02    // IO 断点（x64 不支持，忽略）
#define NPHV_DR_RW_READWRITE    0x03    // 读写断点

//
// ============================ X64DBG 调试链路隐藏（NpDebugHide） ============================
//
// 开启后 Hook 调试相关系统调用：
// - NtQueryInformationProcess：调试检测类返回假值（DebugPort=0 等）；
// - NtWriteVirtualMemory：写 0xCC → 转 NPT 无痕断点（内存不落 CC）；
// - NtReadVirtualMemory：物理直读（真实内容）。
// 只对"受保护进程集"生效（IOCTL_NPHV_DEBUG_PROTECT 注册）。
//

// 开启/关闭调试隐藏
typedef struct _NPHV_DEBUG_HIDE_REQUEST
{
    uint32_t Version;
    uint32_t Enable;                // 0=关闭（卸载 Hook），1=开启
} NPHV_DEBUG_HIDE_REQUEST, *PNPHV_DEBUG_HIDE_REQUEST;

// 注册/注销受保护进程
typedef struct _NPHV_DEBUG_PROTECT_REQUEST
{
    uint32_t Version;
    uint32_t ProcessId;             // 调试目标 PID
    uint32_t Protect;               // 1=保护，0=注销
    uint32_t Reserved;
} NPHV_DEBUG_PROTECT_REQUEST, *PNPHV_DEBUG_PROTECT_REQUEST;

// 调试隐藏模式
#define NPHV_DEBUG_MODE_WHITELIST  0x00000000  // 白名单：仅注册的 PID 隐藏（默认）
#define NPHV_DEBUG_MODE_BLACKLIST  0x00000001  // 黑名单：除注册的 PID 外全部隐藏

// 切换隐藏模式
typedef struct _NPHV_DEBUG_MODE_REQUEST
{
    uint32_t Version;
    uint32_t Mode;                  // NPHV_DEBUG_MODE_*
} NPHV_DEBUG_MODE_REQUEST, *PNPHV_DEBUG_MODE_REQUEST;

//
// ============================ B层 调试器进程隐藏（NpProcessHide） ============================
// Hypervisor 层过滤 NtQuerySystemInformation(SystemProcessInformation)
// 只藏进程名，不触 R3。
//
#define IOCTL_NPHV_PROCESS_HIDE         CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PROCESS_HIDE_ADD     CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 19, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PROCESS_HIDE_REMOVE  CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PROCESS_HIDE_CLEAR   CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PROCESS_HIDE_LIST    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 查看者豁免：名单内进程发起的进程枚举不做隐藏过滤（自家调试器要能看见目标）
#define IOCTL_NPHV_PROCESS_WATCH_ADD     CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PROCESS_WATCH_REMOVE  CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 24, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PROCESS_WATCH_LIST    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 25, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 用户态隐匿补丁（方案C-PatchView）：执行走克隆（改后），读取按观察者分流
#define IOCTL_NPHV_PATCH_INSTALL         CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 26, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PATCH_REMOVE          CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 27, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PATCH_LIST            CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 28, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _NPHV_PATCH_REQUEST {
    uint32_t Version;
    uint32_t TargetPid;              // 被补丁的进程
    uint64_t Va;                     // 目标地址
    uint32_t Length;                 // ≤ 512
    uint32_t Reserved;
    uint8_t  Bytes[512];             // 新字节（REMOVE 时忽略）
} NPHV_PATCH_REQUEST, *PNPHV_PATCH_REQUEST;

#define NPHV_PATCH_MAX_LEN 512

typedef struct _NPHV_PATCH_ITEM {
    uint64_t Va;                     // 补丁起始 VA（页内任一已应用点）
    uint32_t Length;                 // 该点长度
    uint32_t VictimPid;
} NPHV_PATCH_ITEM;

typedef struct _NPHV_PATCH_LIST_RESPONSE {
    uint32_t Status;
    uint32_t Count;
    uint32_t Reserved[2];
    struct {
        uint64_t Va;
        uint32_t Length;
        uint32_t VictimPid;
    } Items[16];
} NPHV_PATCH_LIST_RESPONSE, *PNPHV_PATCH_LIST_RESPONSE;

typedef struct _NPHV_PROCESS_HIDE_REQUEST {
    uint32_t Version;
    uint32_t Enable;
} NPHV_PROCESS_HIDE_REQUEST, *PNPHV_PROCESS_HIDE_REQUEST;

typedef struct _NPHV_PROCESS_HIDE_NAME_REQUEST {
    uint32_t Version;
    wchar_t Name[64];
} NPHV_PROCESS_HIDE_NAME_REQUEST, *PNPHV_PROCESS_HIDE_NAME_REQUEST;

typedef struct _NPHV_PROCESS_HIDE_LIST_RESPONSE {
    uint32_t Status;
    uint32_t Enabled;
    uint32_t Count;
    uint32_t Reserved;
    wchar_t Names[16][64];
} NPHV_PROCESS_HIDE_LIST_RESPONSE, *PNPHV_PROCESS_HIDE_LIST_RESPONSE;

#ifdef __cplusplus
}
#endif


//
// ============================ P2/P4/P5 新架构 IOCTL（从 +29 起） ============================
//

// 伪附加：attach（29）/ wait（30）/ continue（31）/ detach（34）/ status（35）
#define IOCTL_NPHV_PSEUDO_ATTACH    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 29, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PSEUDO_WAIT      CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PSEUDO_CONTINUE  CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 31, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_VHOOK_INSTALL    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 32, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_LSTAR_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PSEUDO_DETACH    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 34, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_PSEUDO_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 35, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_VHOOK_REMOVE     CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 36, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_VHOOK_LIST       CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 37, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DATA_PATCH_INSTALL CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 38, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DATA_PATCH_REMOVE  CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 39, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_DATA_PATCH_LIST    CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 40, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NPHV_SYSCALL_PRECHECK   CTL_CODE(FILE_DEVICE_UNKNOWN, NPHV_IOCTL_BASE + 41, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NPHV_PSEUDO_MAX_SESSIONS_CTL 16
#define NPHV_VHOOK_MAX_ENTRIES_CTL   16
#define NPHV_DATA_PATCH_MAX_ENTRIES_CTL 16

typedef struct _NPHV_PSEUDO_ATTACH_REQUEST {
    uint32_t Version;
    uint32_t TargetPid;
} NPHV_PSEUDO_ATTACH_REQUEST;

typedef struct _NPHV_PSEUDO_ATTACH_RESPONSE {
    uint32_t SessionId;
    uint32_t Status;
} NPHV_PSEUDO_ATTACH_RESPONSE;

typedef struct _NPHV_PSEUDO_DETACH_REQUEST {
    uint32_t Version;
    uint32_t SessionId;
} NPHV_PSEUDO_DETACH_REQUEST;

typedef struct _NPHV_PSEUDO_SESSION_ENTRY {
    uint32_t SessionId;
    uint32_t TargetPid;
    uint32_t DebuggerPid;
    uint32_t EventCount;
} NPHV_PSEUDO_SESSION_ENTRY;

typedef struct _NPHV_PSEUDO_STATUS_RESPONSE {
    uint32_t Status;
    uint32_t Count;
    NPHV_PSEUDO_SESSION_ENTRY Entries[NPHV_PSEUDO_MAX_SESSIONS_CTL];
} NPHV_PSEUDO_STATUS_RESPONSE;

typedef struct _NPHV_VHOOK_INSTALL_REQUEST {
    uint32_t Version;
    uint32_t ProcessId;             // 0 = 内核
    uint64_t TargetVa;
    uint32_t PatchLen;              // 1..512
    uint32_t Reserved;
    uint8_t Bytes[512];
} NPHV_VHOOK_INSTALL_REQUEST;

typedef struct _NPHV_VHOOK_INSTALL_RESPONSE {
    uint32_t HookId;
    uint32_t Status;
    uint64_t CaveVa;
} NPHV_VHOOK_INSTALL_RESPONSE;

typedef struct _NPHV_VHOOK_REMOVE_REQUEST {
    uint32_t Version;
    uint32_t HookId;
} NPHV_VHOOK_REMOVE_REQUEST;

typedef struct _NPHV_VHOOK_ENTRY {
    uint32_t HookId;
    uint32_t ProcessId;
    uint64_t TargetVa;
    uint64_t CaveVa;
    uint32_t PatchLen;
    uint32_t Reserved;
} NPHV_VHOOK_ENTRY;

typedef struct _NPHV_VHOOK_LIST_RESPONSE {
    uint32_t Status;
    uint32_t Count;
    NPHV_VHOOK_ENTRY Entries[NPHV_VHOOK_MAX_ENTRIES_CTL];
} NPHV_VHOOK_LIST_RESPONSE, *PNPHV_VHOOK_LIST_RESPONSE;

typedef struct _NPHV_DATA_PATCH_INSTALL_REQUEST {
    uint32_t Version;
    uint32_t TargetPid;
    uint64_t Va;
    uint32_t Flags;                 // NPHV_DATA_PATCH_READ_POINT / PAGE_SHADOW
    uint32_t Length;                // 1..512
    uint8_t Bytes[512];
} NPHV_DATA_PATCH_INSTALL_REQUEST;

typedef struct _NPHV_DATA_PATCH_INSTALL_RESPONSE {
    uint32_t PatchId;
    uint32_t Status;
} NPHV_DATA_PATCH_INSTALL_RESPONSE;

typedef struct _NPHV_DATA_PATCH_REMOVE_REQUEST {
    uint32_t Version;
    uint32_t PatchId;
} NPHV_DATA_PATCH_REMOVE_REQUEST;

typedef struct _NPHV_DATA_PATCH_ENTRY {
    uint32_t PatchId;
    uint32_t TargetPid;
    uint64_t Va;
    uint32_t Flags;
    uint32_t Length;
} NPHV_DATA_PATCH_ENTRY;

typedef struct _NPHV_DATA_PATCH_LIST_RESPONSE {
    uint32_t Status;
    uint32_t Count;
    NPHV_DATA_PATCH_ENTRY Entries[NPHV_DATA_PATCH_MAX_ENTRIES_CTL];
} NPHV_DATA_PATCH_LIST_RESPONSE, *PNPHV_DATA_PATCH_LIST_RESPONSE;

#define NPHV_DATA_PATCH_READ_POINT   0x00000001
#define NPHV_DATA_PATCH_PAGE_SHADOW  0x00000002

typedef struct _NPHV_LSTAR_STATUS_RESPONSE {
    uint64_t OrigLstar;
    uint64_t Trampoline;
    uint32_t Hooked;
    uint32_t InterceptCount;
} NPHV_LSTAR_STATUS_RESPONSE;

// P0 syscall 预检（R3 镜像，与内核 NPSYSCALL_PRECHECK_RESULT 对应）
#define NPHV_SYSCALL_PRECHECK_COUNT 7
typedef struct _NPHV_SYSCALL_PRECHECK_ENTRY {
    char Name[48];
    uint64_t Address;
    uint32_t Syscall;
    uint32_t IsSyscall;
    uint32_t Resolved;
    uint32_t Reserved;
} NPHV_SYSCALL_PRECHECK_ENTRY;

typedef struct _NPHV_SYSCALL_PRECHECK_RESPONSE {
    uint32_t Status;
    uint32_t Count;
    uint32_t AllPassed;
    uint32_t TableCrossChecked;
    uint64_t ServiceTable;
    uint64_t ModuleBase;
    uint32_t Is4B;
    uint32_t Reserved;
    NPHV_SYSCALL_PRECHECK_ENTRY Entries[NPHV_SYSCALL_PRECHECK_COUNT];
} NPHV_SYSCALL_PRECHECK_RESPONSE;
