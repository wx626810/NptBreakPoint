/*!
    @file       NpConfig.h

    @brief      编译期配置中心。所有可调参数集中于此，不散落各模块。
 */
#pragma once

//
// 反检测模式：默认开启。
// 开启后 CPUID/EFER/VM_CR 等对 Guest 伪装成“无 Hypervisor”状态；
// 关闭后镜像 SimpleSvm 的行为（设置 Hypervisor Present 位、报告厂商名），
// 便于调试时用 CPUID 验证 Hypervisor 是否在位。
#ifndef NPTHOOK_STEALTH
#define NPTHOOK_STEALTH 1
#endif

// NPT 恒等映射的地址空间大小（GB）。消费级 AMD 平台 512GB 足够。
#ifndef NPTHOOK_NPT_MAP_GB
#define NPTHOOK_NPT_MAP_GB (512)
#endif

// Hook 触发后复位线程的间隔（毫秒）。影子页暴露窗口由此控制。
#ifndef NPTHOOK_RESET_INTERVAL_MS
#define NPTHOOK_RESET_INTERVAL_MS (5)
#endif

// 隐匿功能（debug-hide / prochide）活跃时的复位间隔（毫秒）。断点 CC 副本
// 与 Hook C 态页面窗口由此兜底；配合"下一次 VMEXIT 快速收紧"，纯页内循环
// 无 VMEXIT 时以该值作为窗口上限。越小开销越高。
#ifndef NPHV_STEALTH_RESET_MS
#define NPHV_STEALTH_RESET_MS (1)
#endif

// 卸载时"排空窗口"长度（毫秒）：等待仍在跳板/影子页上的存量线程执行完毕。
// Hook 已摘除后无新跳板进入；回调仅微秒级，200ms 足够。窗口期间虚拟化
// 必须保持开启，否则残留线程的跳板尾部 vmmcall 会因 SVME 关闭而 #UD。
#ifndef NPTHOOK_UNLOAD_DRAIN_MS
#define NPTHOOK_UNLOAD_DRAIN_MS (200)
#endif

// 序言复制的最小长度（字节）。与经典 Inline Hook 规则一致：
// 至少复制 5 字节、且落在指令边界上。
#ifndef NPTHOOK_MIN_PROLOG_SIZE
#define NPTHOOK_MIN_PROLOG_SIZE (5)
#endif

// 演示 Hook 是否自动安装（驱动加载时 Hook NtQuerySystemInformation）。
// 默认关闭：框架交付后由 R3 管理通道（IOCTL）按需安装 Hook。
#ifndef NPTHOOK_INSTALL_DEMO_HOOKS
#define NPTHOOK_INSTALL_DEMO_HOOKS 0
#endif

// 每 CPU 预留的大页拆分用 PT 页数量（每个 2MB 区域拆一次用一页）。
// 安装/触发时从该池取页（VMEXIT 上下文绝不分配内存）。
#ifndef NPTHOOK_MAX_SPLIT_PT_PER_CPU
#define NPTHOOK_MAX_SPLIT_PT_PER_CPU (64)
#endif

// 日志落盘路径（services/NpLog）。
#ifndef NP_LOG_FILE_PATH
#define NP_LOG_FILE_PATH L"\\??\\C:\\Windows\\NpHv.log"
#endif

// 调试器输出前缀（services/NpLog 的 NpDebugPrint）。
#ifndef NP_DEBUG_PREFIX
#define NP_DEBUG_PREFIX "[NpHv] "
#endif

// 全局日志开关：0 = 编译期剔除全部日志（NpHvLogPrint/NpLogPrint/NpDebugPrint
// 变为空操作，不分配缓冲、不建落盘线程、不写任何文件）；1 = 启用。
#ifndef NPTHOOK_LOG_ENABLE
#define NPTHOOK_LOG_ENABLE 1
#endif

// 驱动自隐藏（加载后从 PsLoadedModuleList 等内核模块列表摘除自身）。
// 1=开启（由运行时变量 g_SelfHide 承载）；0=关闭
// R3-R0 无设备通信（VMMCALL双栈，WinObj零设备）
#ifndef NPT_NO_DEVICE
#define NPT_NO_DEVICE 0
#endif

#ifndef NPTHOOK_SELF_HIDE
#define NPTHOOK_SELF_HIDE 1
#endif
