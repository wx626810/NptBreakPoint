# NpHv 0xCE 启动蓝屏修复 & prochide 名单查询修复报告

> 基线：修复后构建 —— `output\NpHv.sys`（Release, 58,488B, 2026-08-25 03:22）/ `output\NpHv.pdb`
> 现象来源：测试机 Win11 24H2 (26100) 单核 VM，WinDbg 管道内核调试（`\\.\pipe\com_1`）全程捕获。
> 结论先行：两条独立 bug 叠加 —— **设备名宏转义丢失**（触发器）+ **DriverEntry 失败路径裸 return**（放大器）。

---

## 一、崩溃现场（KD 捕获）

```
[NpHv] NptHook loading...
[NpHv] Service 'devioctl' init failed: 0xc000003b     ← STATUS_OBJECT_PATH_SYNTAX_BAD
*** Fatal System Error: 0x000000ce
Driver at fault: NpHv.sys.
IP_MODULE_UNLOADED: <Unloaded_NpHv.sys>+0x9dec        ← 已卸载镜像内取指
FAULTING_THREAD / PROCESS_NAME: System                 ← 系统线程仍在跑驱动代码
```

`!analyze`：MiSystemFault 先按 0x50（PAGE_FAULT_IN_NONPAGED_AREA）上报，内核发现出错 IP 落在
最近卸载的 NpHv 镜像区间，转牌为 **0xCE DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS**。

## 二、根因链

### Bug 1（触发器）：设备名宏转义丢失 —— NpIoctl.h L29-30

```c
#define NPHV_DEVICE_NAME     L"\Device\NpHv"      // \D、\N 为未定义转义
#define NPHV_DOS_DEVICE_NAME L"\DosDevices\NpHv"
```

C 标准中未定义转义由实现定义处理，MSVC（C4129）丢弃反斜杠保留字母：
实际字符串为 `"DeviceNpHv"` / `"DosDevicesNpHv"`——**没有前导反斜杠**。
`IoCreateDevice` 对非全路径名直接返回 `STATUS_OBJECT_PATH_SYNTAX_BAD (0xC000003B)`，
与 KD 日志失败码完全一致。

该宏为 R3 管理通道（devioctl 服务）引入时新增；v1 known-good 备份中无设备对象代码，
即此 bug 自该功能诞生起就存在——**新代码下驱动从未成功启动过**（此前 GUI 一直提示
"无法打开 \\.\NpHv" 即此因，被误判为"驱动未启动"而非"启动必失败"）。

### Bug 2（放大器）：虚拟化前服务 Init 失败路径裸 return —— NptHook.cpp DriverEntry

时序：

1. 服务表首项 `log` → `NpLogInitialize()` 启动日志落盘系统线程
   （`PsCreateSystemThread`，NpLog.cpp L272；线程归属 System 进程 ✓ 与 dump 的
   FAULTING_THREAD/PROCESS_NAME 吻合）；
2. `devioctl` → `NpDevInitialize()` 因 Bug 1 失败；
3. 失败分支 **裸 `return status`**，跳过全部回滚；
4. 内核在 DriverEntry 失败后释放镜像，log 线程仍存活并在下次唤醒时执行已释放代码
   → 页错误 `<Unloaded_NpHv.sys>+0x9dec` → 0x50 → 转牌 0xCE。

对照：同函数内电源回调/虚拟化/复位线程的失败点均正确 `goto Exit` 回滚，
唯独服务初始化循环与 `NpHvInitialize` 两处遗漏。

### 附带澄清

- 日志中 `uiomap`、`NetworkPrivacyPolicy` 报 `0xc00000bb`（STATUS_NOT_SUPPORTED）
  为测试机遗留第三方驱动自身问题，与本框架无关。
- 本例同时验证：**凡能转化为 bugcheck 的崩溃，管道 KD 均可完整捕获**
  （含 0x50→0xCE 转牌过程），与《无痕断点人工手册》调试章节结论一致；
  三重故障类复位仍是 KD 盲区。

## 三、修复内容

| # | 文件 | 修改 |
|---|---|---|
| 1 | `NptHook\include\NpIoctl.h` | 设备名宏改为 `L"\\Device\\NpHv"` / `L"\\DosDevices\\NpHv"`，加注释防回归 |
| 2 | `NptHook\NptHook.cpp` | 虚拟化前服务 Init 失败分支：逆序 Teardown 已初始化服务后再返回（失败的 i 由其 Init 内部自清理） |
| 3 | `NptHook\NptHook.cpp` | `NpHvInitialize()` 失败分支：同样回滚非 PostVirtualize 服务后返回 |

## 四、验证

修复后 `sc start NpHv` 正常加载，R3 通道连通，断点/监视/Hook 功能实测正常（用户确认）。
预期启动日志序列：

```
IOCTL device \Device\NpHv created.
All processors virtualized (N).
NptHook loaded successfully.
```

## 五、同场修复：prochide 查看名单名字为空

**现象**：`prochide add msedge.exe` 后 list 显示 `count=7` 但 `[0]..[6]` 全空串。
（count=7 = 6 个预置默认名 x64dbg.exe/x32dbg.exe/x64dbg.dll/x32bridge.dll/
TitanEngine.dll/scylla_hide.dll + 用户添加的 msedge.exe，属预期行为。）

**根因**：`NpDevIoctl.cpp` 的 `IOCTL_NPHV_PROCESS_HIDE_LIST` 分支为未完成的桩——
仅填充 `Enabled/Count`，注释自述"简化为仅数量，名字留空"。R3 端打印逻辑无误。

**修复**：

- `NpProcessHide.h/.cpp` 新增 `NpProcessHideCopyNames(Names, MaxEntries)`：
  全程持 `g_HideLock` 拷贝到 METHOD_BUFFERED 系统缓冲，单名截断 63 字符+NUL，
  返回实际条数；
- IOCTL 分支改调该函数，`Count` 以实际拷贝数为准（保证 Count 与 Names 一致）。

验证命令：`NpHvCtl prochide list` / GUI"查看名单"，应逐行显示注册名。

## 六、后续建议（未实施）

1. **致命路径主动转 bugcheck**：VMEXIT_INVALID / #NPF 处理失败等兜不住的错误
   `KeBugCheckEx(自定义码, exit_code, guest_rip, gpa)`，把"三重故障复位"（KD 盲区）
   转化为可捕获现场；
2. **VMexit 黑匣子**：非分页环形缓冲记录 exit code/guest RIP，bugcheck 后 `.writemem` 导出;
3. **受保护进程集 PID 复用清理**：`g_ProtectedPids` 存裸 PID，配合
   `PsSetCreateProcessNotifyRoutine` 在进程退出时清槽；
4. **drprobe/KD 冲突防御**：`NpBreakPointSetDrProbe` 入口检测
   `SharedUserData->KdDebuggerEnabled`，KD 在线时告警或拒绝开启；
5. **监视点上报**：DEBUGGER 场景下监视命中按 CR2 匹配区间注入 #DB 并同步 FakeDr6，
   补齐硬件断点语义（当前仅执行断点有事件上报）。

---
分析/修复：ox-alpha，2026-08-25。构建：MSBuild Release x64，0 error。
