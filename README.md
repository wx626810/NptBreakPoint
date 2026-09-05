# NptBreakPoint — 基于 AMD NPT 的无痕内核 Hook / 断点框架

基于 AMD NPT 的无痕内核 Hook / 断点框架，供学习与研究使用。

包含两个子项目：

| 目录 | 内容 |
|------|------|
| `NptHook/`（根目录） | R0 内核驱动（NpHv.sys） |
| `NpHvCtl/` | R3 命令行管理工具（NpHvCtl.exe，MinGW 编译） |
| `NpDrvInst/` | 安装 DLL（NpDrvInst.dll，BYOVD 链路安装/卸载） |

`NpHvCtl/HwRwDrv.sys` 为已知漏洞驱动（BYOVD），用于 CI 补丁后加载 NpHv；
`NpHvCtl/embedded_drivers.h` 为编译后驱动字节（XOR 混淆），重新编译驱动后
运行 `tools/embed_drivers.py` 更新。

## 构建要求

- Visual Studio 2022（含 C++ 桌面开发工作负载）
- WDK for Windows 10/11（建议 10.0.22621+）
- AMD 处理器（SVM + NPT 支持）

## 构建

```bat
python run_build.py Release Build
```

或直接用 MSBuild 打开 `NptHook.sln` 编译。

## 能力概览

| 能力 | 说明 |
|------|------|
| 无痕 Hook | 三态 NPT 状态机，不改目标内存一个字节 |
| 无痕断点 | 自动单步 / HALT / 单次，不占 DR0-3 |
| NPT 监视 | 页级 R/W 陷阱，模拟无限硬件断点 |
| 无痕读写 | PID → CR3 → 页表遍历 → 物理直读 |
| DR 虚拟化 | X64DBG 硬件断点自动转 NPT，真 DR 永远干净 |
| 调试器适配 | 附加自动保护、F2/F8/F9 全透传 |
| 自隐藏 | DKOM 摘链 + QSI 过滤 + 无设备化 |

## 反检测

Hypervisor 对 Guest 伪装为"不存在"：CPUID 叶子隐身、MSR 直通层伪装、
VMCB 标志位清理。模块自隐藏（DKOM PsLoadedModuleList + QSI 过滤）默认开启。

## 使用

驱动加载后自动虚拟化全部处理器，通过 `\\.\NpHv` 设备对象接受 R3 管理工具控制。
详见 `docs/NpHvCtl-命令参考.md`。

## 参考

- [SimpleSvm](https://github.com/tandasat/SimpleSvm) — AMD SVM 教学 Hypervisor 骨架
- [SimpleSvmHook](https://github.com/tandasat/SimpleSvmHook) — NPT 隐身 Hook
- AMD64 Architecture Programmer's Manual Vol.2 — SVM/NPT 权威规范



## License

本项目基于 GPL-3.0 开源。
