# NpHv 已验证版本与备份记录

> 记录：**哪些版本在测试机上真实运行验证过**、备份在哪里、如何恢复。
> 创建：2026-08-16（v2.3 蓝屏事件后整理）

---

## 1. 唯一经测试机运行验证的版本：v1（git `a0fc415`）

| 项 | 值 |
|---|---|
| git 基线 | `a0fc415`（`a0fc4153cc0468ba15c899a3bc64f618911b0393`）|
| commit message | `v1: working NPT hook (4-core virtualized, 2600+ intercepts verified)` |
| 验证时间 | 2026-08-13（重构开始前，用户告知）|
| 验证环境 | 测试机（AMD SVM/NPT）|
| **验证内容** | **4 核虚拟化成功**（VMRUN 全部处理器）+ **2600+ 次 Hook 拦截无崩溃**（演示 Hook 挂 NtQuerySystemInformation，跑 tasklist 等高频触发）|

**结构**：重构前的单文件形态——`NptHook.cpp`（1892 行）+ `HookManager.cpp`（1166 行）+ `Disasm.cpp`（586 行）+ `x64.asm` + `NptHook.hpp`（612 行）。

---

## 2. 备份位置（双保险）

| 备份 | 位置 | 说明 |
|---|---|---|
| **git tag（权威）** | `known-good-v1` → `a0fc415` | 随仓库走，永不丢失；`git checkout known-good-v1` 即恢复 |
| **物理快照（可部署）** | `backups/NpHv-v1-known-good-a0fc415/`（36 MB）| 完整含构建产物（x64\Release\NptHook.sys），可独立拷贝到测试机 |

**恢复方法**：
```bat
rem 方式 A：git 恢复
git checkout known-good-v1

rem 方式 B：直接拷快照（含编译好的 .sys）
copy backups\NpHv-v1-known-good-a0fc415\x64\Release\NptHook.sys C:\Windows\System32\drivers\
```

---

## 3. 版本状态总表

| 版本 | git 基线 | 编译 | **测试机运行验证** | 说明 |
|---|---|---|---|---|
| **v1** | `a0fc415` | ✅ | ✅ **4 核 + 2600+ 拦截无崩** | **唯一运行验证版（known-good）** |
| v2 | `29797d8` | ✅ | ❌ 未验证 | 四层架构重构（逻辑原样迁移）|
| v2.1 | `83dd469` | ✅ | ❌ 未验证 | 更名 NpHv.sys / NpHv.log |
| v2.2 | `80858ab` | ✅ | ❌ 未验证 | arch 层拆分（NpHvArchSvm.cpp）|
| v2.3 | `d0e6cb8` | ✅ | ❌ 未验证 | R3 管理通道（**引入 IoCreateDevice bug**）|
| v2.4 | `29e1421` | ✅ | ❌ 未验证 | CustomCode 代码注入 |
| v2.5 | `1df8d1c` | ✅ | ❌ 未验证 | 驱动自隐藏（默认关）|
| — | `679e53c` | ✅ | ❌ 未验证 | SELF_HIDE 默认 0 |
| **当前** | `ff1a570` | ✅ | ✅ **2026-08-16 复验通过** | 修复 0x50 蓝屏；`status`：hypervisor running **yes**、4 核 |

---

## 4. 蓝屏事件记录（为什么需要这份记录）

**事件**：2026-08-16 01:11，测试机 `sc start NpHv` 加载后蓝屏。

- **bugcheck**：`PAGE_FAULT_IN_NONPAGED_AREA (0x50)`，写 `0xffffffffffffffd0`
- **栈**：`NpHv+0x3e2c → nt!IoCreateDevice+0x36b → nt!ObfReferenceObject → lock xadd [rsi-30h]`（rsi=0）
- **根因**：v2.3 的 `NpDevInitialize` 里 `IoCreateDevice(nullptr, ...)` —— DriverObject 传 NULL，IoCreateDevice 内部对 NULL 做对象引用 → 空解引用蓝屏
- **为何 v1 没崩**：v1 没有设备对象（R3 通道是 v2.3 才加的）；且本机无 AMD SVM，冒烟测试到不了 IoCreateDevice 路径
- **修复**：`ff1a570` —— 新增 `g_DriverObject`，`NpDevRegisterDispatchers` 保存（早于服务 Init 调用），`NpDevInitialize` 使用

**核心教训**：v1 之后所有版本都只有编译层验证、无运行验证。**"编译通过 ≠ 能跑"**——本次蓝屏是运行验证暴露的第一个 bug。今后每个改动版本在测试机复验通过前，v1 备份不得删除。

---

## 5. 部署与复验流程（建议固化）

```bat
rem ① 先在测试机确认 v1 可回滚（已备份）
rem ② 部署待验证版本
copy /Y x64\Release\NpHv.sys C:\Windows\System32\drivers\
sc stop NpHv & sc start NpHv
rem ③ 复验功能
NpHvCtl status        ; hypervisor running: yes
NpHvCtl demo          ; 装 Hook → 触发 → 卸载
rem ④ 通过后更新本表（把版本行改为 ✅）
```
