# NpHv 框架架构报告

> 基于 AMD NPT 的无痕内核 Hypervisor 框架 — 架构设计、关键机制与扩展指南
>
> 版本：v2.2（arch 层拆分完成） · 日期：2026-08-13

---

## 1. 项目概述

NpHv 是一个基于 **AMD SVM + NPT（嵌套页表）** 的内核 Hypervisor 框架，核心能力是"**无痕 Hook**"：不修改任何 Guest 内存字节，通过 Hypervisor 持有的 NPT 控制"同一个 GPA 在不同时刻映射到不同的 HPA"，从而让数据读看到干净代码、指令执行看到 INT3，实现执行流劫持且对检测方不可见。

**定位**：不是一次性 Demo，而是**可扩展的框架**——新功能通过 handler 注册、服务注册、事件订阅接入，不动核心。

**参考实现**：SimpleSvm（tandasat，极简 SVM Hypervisor）、SimpleSvmHook（tandasat，NPT Hook 功能实现）、看雪《从 0 到 1 实现 NPT 无痕 Hook》。

**当前状态**：功能验证通过（4 核虚拟化、演示 Hook 拦截 NtQuerySystemInformation 2600+ 次无崩），Debug/Release 全量编译零错误。

---

## 2. 架构设计

### 2.1 分层模型

```
┌────────────────────────────────────────────────────────────┐
│ demo/    业务层：DemoHook.cpp（演示 Hook）                   │
│          新功能模块放这里，登记服务表即可                     │
├────────────────────────────────────────────────────────────┤
│ services/ 服务层：NpLog（分级日志）、NpHook（三态状态机）、    │
│           NpDisasm（指令解码器）                             │
├────────────────────────────────────────────────────────────┤
│ core/    核心层（Ring -1 最小内核）：                        │
│           NpHv.cpp        通用生命周期（架构无关）            │
│           NpHvArchSvm.cpp AMD 专属（SVM/VMCB/NPT）          │
│           NpHvVmExit.cpp  VMEXIT 分发引擎 + handler 注册表   │
│           NpHvPower.cpp   电源回调                          │
│           NpPlatform.cpp  平台抽象（内存/CPU 遍历）           │
│           x64.asm         VM 循环/跳板模板/vmmcall           │
├────────────────────────────────────────────────────────────┤
│ platform/ 运行环境抽象：内存分配、CPU 亲和性遍历              │
└────────────────────────────────────────────────────────────┘
```

### 2.2 依赖规则（单向，禁止反向）

```
demo ──► services ──► core ──► platform
```

- core 不依赖 services/demo
- services 依赖 core 的公开接口（NpHv.h）
- demo 依赖 services + core

### 2.3 目录结构

```
NptHook/
├── NptHook.sln / build.bat / .gitignore
├── docs/                     # 本文档所在目录（报告/设计文档）
├── NptHook/
│   ├── NptHook.hpp           # 聚合头（组装层使用）
│   ├── NptHook.cpp           # 组装层：服务注册表 + DriverEntry/Unload
│   ├── include/              # 9 个模块化头文件
│   ├── core/                 # 核心层（6 源文件）
│   ├── services/             # 服务层（3 模块）
│   ├── demo/                 # 业务层（1 模块）
│   └── tests/                # 解码器单测
└── x64/                      # 构建产物（NpHv.sys）
```

---

## 3. 模块职责

| 模块 | 职责 |
|------|------|
| **NptHook.cpp** | 组装层：服务注册表 `g_Services[]` 按序 Init/Teardown、虚拟化编排、卸载排空/去虚拟化/释放 |
| **core/NpHv.cpp** | 通用生命周期：每 CPU 数据管理、事件广播、全核虚拟化编排、复位线程、NPT 构建入口（委托 arch） |
| **core/NpHvArchSvm.cpp** | **AMD 专属**：SVM/NPT/SVMDIS 检测、MSRPM（反检测拦截位）、NPT 恒等映射构建、VMCB 初始化、单核虚拟化（SvLaunchVm） |
| **core/NpHvVmExit.cpp** | VMEXIT 分发 + handler 注册表；内置处理器：CPUID（后门/隐身）、MSR（EFER/VM_CR/VM_HSAVE_PA 反检测）、NPF/#BP（Hook 状态机）、VMMCALL、VMRUN、SHUTDOWN |
| **core/NpHvPower.cpp** | \Callback\PowerState 电源回调：睡眠去虚拟化、唤醒重虚拟化 + PowerResume 事件 |
| **core/NpPlatform.cpp** | 页对齐/物理连续内存、CPU 亲和性遍历（NpForEachProcessor）、忙等 |
| **core/x64.asm** | SvLaunchVm（VMRUN/VMEXIT 循环）、TrampolineTemplate（跳板模板）、AsmVmmCallResetShadows、AsmGetGdtr/AsmGetIdtr |
| **services/NpLog.cpp** | 分级环形日志（Error/Warn/Info/Trace）+ 落盘线程（C:\Windows\NpHv.log） |
| **services/NpHook.cpp** | Hook 服务：三态状态机、2MB 大页拆分、影子页、跳板生成、安装/卸载/退休链表 |
| **services/NpDisasm.cpp** | x64 指令长度解码器（序言复制长度计算，纯逻辑可单测） |
| **demo/DemoHook.cpp** | 演示 Hook（NtQuerySystemInformation），业务层样板 |

---

## 4. 关键机制

### 4.1 三态 NPT 状态机（每 CPU 独立）

```
A: GPA→影子页0(干净拷贝, NX=1) ──入口取指 NPF──► B: GPA→影子页1(INT3, NX=0)
   ▲                                              │ INT3 → #BP VMEXIT
   └──跳板尾部 vmmcall / 复位线程 ── C: GPA→影子页0(NX=0) ◄──┘ RIP 重定向跳板
```

- **状态 A（默认）**：数据读命中干净拷贝（不泄露 Hook），取指触发 NPF
- **状态 B（触发）**：执行 INT3 → #BP VMEXIT → RIP 重定向到跳板，**当场复位回 A**
- **状态 C（放行）**：跳板执行序言副本后跳回原函数；尾部 vmmcall 复位回 A

**多核一致性**：每 CPU 一棵独立 NPT（`NPT_ROOT` 挂在 `VIRTUAL_PROCESSOR_DATA`），叶子切换原子（InterlockedExchange64）+ ASID 级 TLB 刷新——同一 GPA 在不同核可有不同状态，天然规避共享页表的 TLB shootdown 问题。

### 4.2 VMEXIT handler 注册表（扩展点核心）

```c
typedef BOOLEAN(*NP_VMEXIT_HANDLER)(PVIRTUAL_PROCESSOR_DATA, PGUEST_CONTEXT);
NTSTATUS NpHvRegisterVmExitHandler(ULONG ExitCode, NP_VMEXIT_HANDLER Handler);
```

- 分发器先查注册表，handler 返回 `TRUE` 完全接管 / `FALSE` 回落内置逻辑
- 同一 ExitCode 可注册多个（先注册先调用，任一 TRUE 终止）
- 加"监控类"功能无需改核心分发器

### 4.3 生命周期事件（跨层解耦）

```c
NpHvRegisterEvent(NpHvEventPowerResume, OnPowerResume, NULL);
```

事件：`VirtualizeBegin/End`（每 CPU）、`DevirtualizeBegin/End`、`PowerResume`。电源唤醒后的"重新应用 Hook"走的就是这条事件链路。

### 4.4 服务注册表（组装）

```c
static const NP_SERVICE g_Services[] = {
    { "log",   NpLogInitialize,      NpLogTeardown,      FALSE },  // 虚拟化前
    { "demo",  NpDemoHooksInstall,   NpDemoHooksTeardown, TRUE  },  // 虚拟化后
};
```

DriverEntry 只做：按序 Init → 核心初始化 → 电源回调 → 虚拟化 → 复位线程 → 虚拟化后 Init。Unload 逆序 Teardown。

### 4.5 两阶段卸载（防 use-after-free）

```
摘除 Hook + 恢复恒等（不释放！挂退休链表）
  → 停线程 → 排空 200ms（等存量跳板线程跑完，虚拟化保持开启）
  → 去虚拟化 → NpHookFreeRetiredHooks() 统一释放 → 释放 VpData
```

**严禁在虚拟化开启时立即释放跳板/影子页**——其他 CPU 可能正在执行跳板（use-after-free），且去虚拟化后残留线程的 `vmmcall` 会 #UD。

### 4.6 反检测（NPTHOOK_STEALTH=1 默认开启）

| 检测面 | 伪装 |
|--------|------|
| CPUID Hypervisor Present 位 | 不设置（Guest 视为原生系统） |
| EFER.SVME 读 | 隐藏（Guest 看到 SVM 未启用） |
| EFER.SVME 写 | 强制保留（Guest 无法关闭虚拟化） |
| VM_CR | 伪造 SVMDIS/LOCK（假装 BIOS 已锁定） |
| VM_HSAVE_PA | 模拟未启用 |

### 4.7 架构隔离（AMD/Intel 边界）

- `NpHvArchSvm.cpp` + `NpSvm.h` = AMD 专属；接口契约在 `NpHvArch.h`
- `NpHv.cpp`（生命周期）、`NpHvVmExit.cpp`（分发引擎）、`NpPlatform.cpp`（平台层）架构无关
- **未来 Intel 支持 = 新增 `NpHvArchVmx.cpp` + `NpVmx.h` 实现同一组 NpArch* 接口**，其余零改动

---

## 5. 重构历程

| 版本 | 内容 | git 基线 |
|------|------|----------|
| v1 | 可运行的单文件实现（NptHook.cpp 1809 行），4 核虚拟化 + Hook 拦截验证通过；修复卸载 use-after-free（两阶段卸载） | `a0fc415` |
| v2 | 四层架构重构：include/ 8 子头、core/services/demo 拆分、VMEXIT handler 注册表、服务注册表、生命周期事件、分级日志 | `29797d8` |
| v2.1 | 驱动产物更名 NpHv.sys、日志 NpHv.log、调试前缀 [NpHv]，日志路径收进 NpConfig.h | `83dd469` |
| v2.2 | **arch 层拆分**：AMD 专属逻辑移至 NpHvArchSvm.cpp，NpHv.cpp 纯通用化，新增 NpHvArch.h 契约 | 本文档对应版本 |

---

## 6. 验证结果

- **编译**：Debug/Release 全量 Rebuild 均 exit=0 errors=0（VS2022 17.14 + WDK 10.0.26100）
- **单元测试**：指令长度解码器 127 条手工用例 + 173 条 objdump 真值交叉验证全部通过
- **功能验证**（测试机日志）：
  - 4 核全部虚拟化成功
  - 演示 Hook 安装成功（NtQuerySystemInformation @ 0xFFFFF807824E0FD0，序言 5 字节）
  - Hook 拦截计数持续增长（count 1 → 2600+），class 覆盖 SystemBasicInformation 等多种调用
  - 回调放行路径正确（ret 正常返回），系统全程无蓝屏
- **静态校验**：全部源文件括号平衡检查通过

---

## 7. 扩展指南

### 7.1 新增 VMEXIT 监控

```c
// demo/MyMonitor.cpp
#include "NpHv.h"
static BOOLEAN MyCpuidMonitor(PVIRTUAL_PROCESSOR_DATA Vp, PGUEST_CONTEXT Ctx)
{
    NpLogInfo("CPUID leaf=%lu\n", (ULONG)Ctx->VpRegs->Rax);
    return FALSE;   // FALSE = 继续内置处理；TRUE = 完全接管
}
NTSTATUS MyMonitorInstall(VOID)
{ return NpHvRegisterVmExitHandler(VMEXIT_CPUID, MyCpuidMonitor); }
```

登记进 `g_Services[]`（`PostVirtualize=TRUE`）即可。未拦截事件（CR 读写/IO）需先在 arch 层 VMCB 初始化开拦截位。

### 7.2 新增 MSR 监控

1. `NpArchSvmBuildMsrPermissionsMap` 中对该 MSR 置读/写拦截位
2. 注册 `VMEXIT_MSR` handler（先于内置反检测被调用），检查/修改 `Ctx->VpRegs`

### 7.3 代码隐身 / 反作弊（NPT 叶子形态扩展）

机制已就绪（每 CPU 独立 NPT + 原子叶子切换）。扩展路径：
- 分配"真代码副本"物理页 + "假页/零页"，扩展 `NpHookSetLeaf` 语义为多态叶子
- NPF 数据读分支按调用 CPU 返回该核视图页面——多核一致性由每 CPU 独立 NPT 天然保证

### 7.4 Intel VMX/EPT 支持

新增 `core/NpHvArchVmx.cpp` + `include/NpVmx.h`，实现 `NpHvArch.h` 契约：
`NpArchVmxBuildNestedPageTables / NpArchVmxVirtualizeProcessor / NpArchVmxDevirtualizeProcessor` 等；x64.asm 增加 VMX 进入/退出封装。分发引擎、handler 表、平台层、服务层全部复用。

### 7.5 新增服务

服务 = Init/Teardown 函数对，登记进 `g_Services[]`。分两个阶段：虚拟化前（基础设施）与虚拟化后（业务 Hook，`PostVirtualize=TRUE`）。

### 7.6 R3 管理通道（IOCTL 协议）

R3 通过设备对象 `\\.\NpHv` 下发命令（协议定义 `include/NpIoctl.h`，R3/R0 共享）：

```
R3 (NpHvCtl.exe) ──DeviceIoControl──► R0 NpDevIoctl 服务 ──► NPT 直改 / vmmcall ──► HV
```

- **安装 Hook**：R3 传"函数名 + 动作"（LogOnly/ReturnValue/PassThrough），R0 用
  `MmGetSystemRoutineAddress` 解析或校验内核地址后安装；返回 HookId
- **卸载**：按 HookId；**卸载 HV**：`IOCTL_NPHV_DEVIRTUALIZE`（含排空窗口）
- **安全**：R3 不传可执行代码（动作模板内置）；拒绝用户态地址；HookId 隐藏内核句柄
- **隐蔽性演进**：设备伪装 → IOCTL 加密 → 影子通道 → 全量 VMMCALL 管理通道
- **测试**：`NpHvCtl/`（MinGW 编译，`demo` 命令跑完整流程）

---

## 8. 构建与部署

```bat
build.bat            # Release x64（默认）
build.bat Debug      # Debug x64
```

产物：`x64\Release\NpHv.sys` / `x64\Debug\NpHv.sys`

测试机部署：

```bat
sc create NpHv type= kernel binPath= C:\Windows\System32\drivers\NpHv.sys
sc start NpHv
tasklist                            ; 触发演示 Hook
notepad C:\Windows\NpHv.log         ; 确认 [demo] 计数增长
sc stop NpHv                        ; 两阶段卸载，应正常退出
```

---

---

## 8.5 NpBreakPoint：NPT 无痕断点 / NPT 监视 / 无痕读写（2026-08-18 新增）

由 NptHook 扩展而来的**反反调试**服务（`services/NpBreakPoint.cpp` +
`services/NpMemAccess.cpp`），与 NpHook 共用 NPT 叶子基础设施。

**无痕 INT3 断点**（读内存永远干净、取指才触发）：
```
取指 → 影子页0(NX) → #NPF → 影子页1(0xCC) → #BP VMEXIT → 记录现场
     → 自动单步（RIP 回退 + 影子页0 可执行 + RFLAGS.TF）→ #DB → 重新武装
     → 或 HALT 暂停（NPF 忙循环钉线程）→ vmmcall(VMMCALL_BP_CONTINUE) 继续
```

**NPT 监视（模拟无限硬件断点）**：清目标页 R/W → 数据访问 #NPF → 记录 →
恢复权限 + TF 单步 → #DB 重新收紧。不占 DR0-DR3。

**无痕读写**：PID → CR3（EPROCESS+0x28）→ 遍历 Guest 页表（GVA→GPA，
支持 2MB/1GB 大页）→ MmGetVirtualForPhysical 物理直读，绕过内存管理接口。

**AMD 特有设计**（对照 Intel EPT / kanxue 帖子）：
1. NPT 无 execute-only → 双影子页实现无痕 INT3；
2. 无 MTF → RFLAGS.TF + 拦截 #DB（VMCB vector 1）实现单步；
3. #BP 拦截时 VMCB.Rip 指向 INT3 本身（Intel 用 rip-1）；
4. 读监视（清 R）在 AMD 连取指一起拦；
5. 跨 CPU 改活动 VMCB 有竞态 → HALT 继续走 vmmcall 在本 CPU 上下文完成。

接入点：服务注册表 `"breakpoint"`（PostVirtualize）+ VMEXIT handler 注册
（NPF/#BP/#DB/VMMCALL）+ `NpHvEventPowerResume` 事件（睡眠后重新应用）。

---

## 9. 已知限制与路线图

**限制**
- AMD-only（当前实现）；NPT 无 execute-only 权限，影子页1 存在单条 INT3 的暴露窗口
- 触发频率受复位周期限制（`NPTHOOK_RESET_INTERVAL_MS`，默认 5ms）
- 每 CPU 大页拆分上限 64 个 PT 页
- 回调禁止重入被 Hook 函数；回调在 Guest 上下文执行（IRQL 约束）

**路线图**
- [ ] Intel VMX/EPT 支持（NpHvArchVmx.cpp）
- [ ] 代码隐身：多态 NPT 叶子（真代码/假页/零页）+ 数据读伪造
- [ ] MSR/CPUID 每项 handler 链（细粒度监控）
- [ ] 模块摘除（PsLoadedModuleList/PiDDBCacheTable 隐身）
- [ ] 日志分级过滤 + Windbg 集成辅助

---

## 10. 免责声明

本项目仅用于安全研究与教学目的。虚拟化 Hook 属于 Ring -1 级技术，使用不当可能违反法律与服务条款。请仅在拥有控制权的测试环境（虚拟机）中使用。

---

## 附录 A：已验证版本与备份记录

- **唯一经测试机运行验证的版本**：v1（git `a0fc415`）——4 核虚拟化 + 2600+ 次 Hook 拦截无崩（2026-08-13 用户确认）。v2 起的重构版本均只有编译层验证。
- **备份**：git tag `known-good-v1`（权威）+ 物理快照 `backups/NpHv-v1-known-good-a0fc415/`（36 MB，含 .sys，可直接部署）。
- **2026-08-16 蓝屏**：v2.3 引入 `IoCreateDevice(nullptr)` → 0x50（ObfReferenceObject 空解引用），`ff1a570` 修复，待测试机复验。
- 详细记录（版本状态总表 / 蓝屏分析 / 恢复方法 / 复验流程）：**`docs/NpHv-验证与备份记录.md`**
