# NpHv 进度报告：LSTAR 伪附加 + SSDT 定位问题与解决

- 日期：2026-08-27
- 构建：`output\NpHv.sys` 20:25（Release），`output\NpHv-Debug.sys` 20:25
- 目标环境：Windows 10 26100.1（嵌套虚拟化，AnyHypervisorPresent=1）
- 目标：无痕调试（LSTAR 伪附加 + NPT 无痕断点），当前阶段聚焦
  "拦截表 syscall 号解析 → KiServiceTable 定位 → 原函数地址 → 伪附加"

---

## 1. 当前进度总览

| 模块 | 状态 | 说明 |
|---|---|---|
| 驱动加载/虚拟化 | 完成 | 4 CPU 虚拟化、心跳正常，无冻结 |
| LSTAR 跳板 | 完成 | 14 槽位、miss 直通、hit vmmcall + 分发器 |
| syscall 号解析 | 完成 | ntdll stub 提取 + 缓存，不再依赖用户进程上下文 |
| SSDT / KiServiceTable 定位 | 完成 | 读 KeServiceDescriptorTable 快速路径，4B 表项解码 |
| 原函数地址解析 | 完成 | `TableBase + (entry >> 4)`，windbg 闭环验证 |
| 非受保护 syscall 透传 | 完成 | 跳板恢复用户现场并重新进入 KiSystemCall64 |
| 伪附加（DAP/会话/快照） | 基本完成 | DAP 拦截、会话创建、事件入队已通 |
| x64dbg 附加显示代码 | 进行中 | 事件流已修复，待目标机复测 |

---

## 2. 定位 SSDT 的最终方法

### 2.1 方法链路

```text
IA32_LSTAR (0xC0000082)
  → 真实 KiSystemCall64（hypervisor MSR 拦截返回原值）
  → 反汇编服务分发，找 lea rX,[KeServiceDescriptorTable]
  → 描述符 [0x00] = TableBase（KiServiceTable）
           [0x10] = NumberOfServices
  → 4B 表项 = (offset << 4) | flags
  → 函数地址 = TableBase + (entry >> 4)
```

### 2.2 描述符结构校验

为避免误选 win32k 等其它描述符/伪表，对每个候选做结构校验：

- `NumberOfServices` ∈ [100, 2000]
- `TableBase` 上连续合法条目段长足够大（≥128）
- 前 64 项解码后低位足够多样（排除 `.rdata` 页对齐伪表）

### 2.3 关键验证数据（windbg 实测）

```text
nt!KeServiceDescriptorTable @ fffff805d20018c0
  TableBase        = fffff805d0eda4d0
  NumberOfServices = 0x1e9 (489)

QIP(sc=25) 表项 = 08d13601
解码后偏移     = 0x08d1360
函数地址       = TableBase + 0x08d1360
              = nt + 0xDAB830 == NtQueryInformationProcess 导出地址 ✅
```

---

## 3. 找 SSDT 遇到的问题与解决（按时间顺序）

### 3.1 全镜像扫描导致 GUI/加载线程卡死

- 现象：点"调试隐藏开启"后 GUI 无响应且进程无法终止。
- 原因：`NpSyscallFindServiceTable` 对整份 ntoskrnl 页面级扫描，
  每个函数扫一遍（最多 8 遍）；嵌套虚拟化下慢到分钟级，GUI 线程
  阻塞在 DeviceIoControl 内核路径，无法被 kill。
- 解决：
  - 删除全镜像扫描兜底，快速路径失败直接返回（功能降级不阻塞）；
  - 改为读 `KeServiceDescriptorTable`（LSTAR 反汇编 + 描述符结构校验）。

### 3.2 QIP 锚点对不上：24H2 导出是包装地址

- 现象：`lstar-scan` 找到多个 lea，但 `TableBase + QIP_SC*4 == QIP`
  永远不成立。
- 原因：`MmGetSystemRoutineAddress("NtQueryInformationProcess")` 返回的
  是 Zw 包装/转发地址，不是 SSDT 表项对应的真实处理函数（两者不同：
  RVA 0x9AB830 vs 0x8D1360）。
- 解决：不再依赖 QIP 锚点，改用描述符结构校验选表。

### 3.3 SGetExecutableRange 解析失败

- 现象：`text=0-0 hasText=0`，结构校验被跳过，快速路径失败。
- 原因：PE 段表读取/边界校验在目标机失败（未知字段差异）。
- 解决：段解析失败时回退"合理 RVA 边界"（`[0x1000, SizeOfImage]`），
  再拿不到 SizeOfImage 时用 512MB 宽边界。

### 3.4 表项编码：不是明文 RVA

- 现象：windbg 读到表项 `08d13601 / 03647104 / ...`，按明文 RVA 算
  全部越界，`run=0`。
- 原因：Win11 KiServiceTable 表项 = `(offset << 4) | flags`，内核用
  `sar r11,4; add r10,r11` 解码。
- 解决：`entry >> 4`（有符号算术移位）后再测量/计算。

### 3.5 SizeOfImage 偏移错误

- 现象：`mz` 扫描失败 / 回退边界过小。
- 原因：PE32+ OptionalHeader 里 `SizeOfImage` 在 `+0x38`，代码误用
  `+0x50`（那是 SizeOfStackCommit）。
- 解决：统一改 `+0x38`；`SValidateImage` 对 SizeOfImage 改为可选校验，
  避免一个字段异常丢掉 nt 基址。

### 3.6 地址基准错误：表基址 vs 镜像基址

- 现象：快速路径命中后，QIP 被解析成 `PiControlGetSetDeviceStatus`，
  转发即 Access Violation。
- 原因：表项解码后的偏移是相对 **TableBase**，不是镜像基址；
  内核 `add r10,r11`（r10=TableBase）。
- 解决：`地址 = TableBase + (entry >> 4)`；并验证
  `TableBase + 0x08D1360 == QIP 导出地址`。

### 3.7 nt 基址（mz）定位失败

- 现象：某次启动后 `mz=0`，连快速路径都进不去。
- 解决：优先从 `PsLoadedModuleList` 取 `ntoskrnl.exe` 基址，
  失败才回退 64KB MZ 扫描，并加 PE 字段诊断日志。

### 3.8 sysretq 回错地址：跳板帧与 shadow space 重叠

- 现象：`.cxr` 显示 `rip=rcx=0xC0000001`（分发器返回值），
  `r10/r11/rsp` 正确。
- 原因：跳板把用户 RIP 存在 `[rsp+0x10]`，正好落在调用分发器的
  x64 shadow space `[rsp..rsp+0x18]`，被 C 调用覆盖。
- 解决：跳板帧整体 +0x20（`sub rsp,0x70`），保存区移到
  `[rsp+0x20..0x58]`，vmmcall syscall# 偏移同步改 `guestRsp+0x50`。

### 3.9 从跳板调用真实 Nt* 破坏上下文

- 现象：Explorer 打开文件夹卡、svchost 崩
  （`NtQueryInformationProcess failed` / `Failed to read the peb`）。
- 原因：对非受保护进程，分发器直接调用真实 Nt*；自定义跳板帧
  缺少正常 syscall 陷阱帧/PreviousMode 语义。
- 解决：改为 **透传重入**——分发器置位 `Frame->Reserved='SLTP'`，
  跳板恢复 EAX/RCX/R11/R10/RDX/R8/R9/用户 RSP，`clac/cli/swapgs`
  后重新进入原始 KiSystemCall64；真实内核完整处理该 syscall。

### 3.10 伪附加 Wait 拿不到目标

- 现象：DAP 成功创建会话，但 x64dbg 附加不上。
- 原因：`NtWaitForDebugEvent/DebugContinue` 的 Arg1 是调试对象句柄，
  不是进程句柄；用进程句柄解析 target 返回 0。
- 解决：新增 `NpPseudoDbgFindByDebugger`，按当前调试器 PID 回退定位
  会话/目标。

### 3.11 DEBUG_EVENT 写超 + 同步事件信号丢失

- 现象：x64dbg 能附加但 CPU 窗口空白、下不了断点。
- 原因：
  1. `NPHV_DEBUG_EVENT`(0xB8) 写入真实 `DEBUG_EVENT`(0xA8) 用户缓冲，
     溢出污染 x64dbg 栈；
  2. 会话 Event 是 SynchronizationEvent，快照一次入队多个事件只留
     一个信号，第二次 Wait 永久阻塞。
- 解决：
  - Wait 写入长度上限 `0xA8`；
  - 取走一个事件后若队列仍有剩余，再次 `KeSetEvent`。

---

## 4. 证据链（Evidence → Finding → Path）

### E-001 windbg 描述符/表数据

- source_type: memory（live kernel debugger）
- repro_command: `rdmsr c0000082` / `u <LSTAR> L2` / `dp <desc> L4` /
  `dd <TableBase> L40`
- raw_excerpt:
  ```text
  lea r10,[nt!KeServiceDescriptorTable (fffff805d20018c0)]
  dp: fffff805d20018c0  fffff805d0eda4d0 0000000000000000
                        00000000000001e9 fffff805d0edac78
  dd: 03647104 0390af00 091a9202 071fee00 ...
  ```

### E-002 表项编码验证

- source_type: memory
- raw_excerpt:
  ```text
  QIP(sc=25) = 08d13601
  TableBase + (08d13601 >> 4) = nt + 0xDAB830 == QIP 导出地址
  ```

### E-003 sysretq 回错地址现场

- source_type: memory
- raw_excerpt:
  ```text
  rip=ffffffffc0000001 rcx=ffffffffc0000001
  rsp=0000009e61dfdd68 r10=0000009e61dfdd68 r11=0000000000000246
  ```

### E-004 目标机实际日志（快速路径成功）

- source_type: log
- raw_excerpt:
  ```text
  [syscall] service table via LSTAR fast path = 0xFFFFF807DF0DA4D0 (4B=1)
  [lstar] orig QIP=FFFFF807DF9AB830 RVM=... WVM=... GCT=... SCT=...
  [pseudo] DAP intercepted: tgt=9388 dbg=7552
  [pseudo] create session 2 ...
  ```

### F-001 Win11 4B SSDT 表项为偏移<<4 编码

- severity: info
- category: reverse_algo
- status: validated
- evidence_ids: [E-001, E-002]
- location: `NptHook/services/NpSyscall.cpp`
- impact: 直接决定函数地址计算；编码错误会解析到错误函数并崩溃。
- remediation: 统一 `entry >> 4` + `TableBase + offset`。

### F-002 自定义跳板帧不能直接调用真实 Nt*

- severity: high
- category: design
- status: validated
- evidence_ids: [E-003]
- impact: 非受保护 syscall 转发破坏调用上下文，Explorer/svchost 崩溃。
- remediation: 透传重入原始 KiSystemCall64。

### P-001 完整定位/附加调用路径

- path_type: callflow
- steps:
  1. 驱动加载 → `NpLstarResolveAll`（附着用户进程解析 syscall 号）
  2. `NpLstarRefresh` → `NpSyscallFindServiceTable` 快速路径
  3. 描述符结构校验 → `TableBase + (entry>>4)` 得到原函数
  4. 用户附加 → DAP 拦截 → 伪会话 + 快照事件
  5. WaitForDebugEvent → 伪会话事件队列 → DEBUG_EVENT 写用户缓冲
  6. 非受保护调用 → 跳板透传重入 KiSystemCall64
- residual_risks:
  - x64dbg 事件流/断点闭环仍需目标机复测；
  - KPTI 探测仍为启发式（当前环境 KPTI off）。

---

## 5. 当前剩余问题 / 下一步

1. x64dbg 附加后 CPU 窗口显示代码、可下断点 —— 需目标机复测
   （20:25 构建已修 DEBUG_EVENT 写超与事件信号丢失）。
2. 断点闭环：WVM 写 0xCC → NPT 无痕断点 → 命中事件 → Continue。
3. 伪会话多目标/句柄映射：当前按调试器 PID 回退，单目标可用。
4. `NpPseudoDbgWaitEvent` 事件流日志已加，下一轮可直接确认。

## 6. 涉及文件

- `NptHook/services/NpSyscall.cpp`：SSDT 快速路径、表项解码、缓存
- `NptHook/services/NpLstar.cpp`：跳板、透传重入、分发器、vmmcall 现场
- `NptHook/services/NpPseudoDbg.cpp`：伪会话、事件队列、Wait/Continue
- `NptHook/services/NpDebugHide.cpp`：受保护目标伪造/处理
- `docs/NpHv-新架构待改动报告-20260827.md`：逐版本踩坑记录（8.15–8.42）

---

## 7. 2026-08-27 21:10 追加：x64dbg 附加后“看不到代码/下不了断点”根因与修复

对照 x64dbg 全量源码（`x64dbg-development/src/dbg`）与 TitanEngine 源码，确认
伪附加走 `AttachDebugger -> DebugLoop -> WaitForDebugEvent` 的流程本身没有误判，
问题出在伪事件载荷与 x64dbg 期望不一致：

### 根因

1. `NPHV_DEBUG_EVENT.Exception` 联合体布局错误：旧结构把 `hThread/hProcess`
   放在异常记录前面，导致 x64dbg 看到的 `ExceptionCode` 是句柄低 32 位
   （如 `0xB8`）而不是 `0x80000003`，`ExceptionAddress` 变成 `0x80000003`，
   CPU 窗口自然定位到无代码的地址。真实 `EXCEPTION_DEBUG_INFO` 只是
   `EXCEPTION_RECORD + dwFirstChance`，不含句柄。
2. 事件写入上限按 `0xA8` 截断，真实 x64 DEBUG_EVENT 是 `0xB0`，
   `dwFirstChance` 落在截断区，x64dbg 会把首次机会断点当成最后一次机会。
3. `FindMainThread` 读错 `SYSTEM_PROCESS_INFORMATION` 偏移（PID 用 +0x08，
   实际 x64 是 +0x50），导致主线程 TID 恒为 0、`hThread` 无效，x64dbg 线程表
   只有一条空线程，活动线程/上下文全失效，CPU 视图空白。
4. CREATE_PROCESS 缺少 `lpStartAddress / lpThreadLocalBase / hFile`，
   也没有 CREATE_THREAD 事件；LOAD_DLL 的 hFile 用 Win32 路径直接
   `ZwOpenFile`，打开必然失败。

### 修复（已编译 Debug/Release，output 已更新）

- `NPHV_DEBUG_EVENT` 按真实 `DEBUG_EVENT` 重排，异常事件改为
  `EXCEPTION_RECORD + dwFirstChance`，并新增 `CreateThread` 联合体；
  经宿主机 MSVC 逐字段验证，`sizeof = 0xB0` 且全部偏移与 `DEBUG_EVENT` 一致。
- 线程枚举改为正确偏移（PID @+0x50、Threads @+0x100、
  `ClientId.UniqueThread` @+0x30），快照输出 CREATE_PROCESS +
  CREATE_THREAD + LOAD_DLL + 初始 EXCEPTION_BREAKPOINT。
- CREATE_PROCESS 补齐入口地址/TEB/映像 hFile；LOAD_DLL hFile 改走
  `\??\` NT 路径；事件容量提高到 256。

### 复测要点（目标机）

- 日志应出现 `[pseudo] snapshot tgt=... threads=N main=...`，N 非 0。
- x64dbg 附加后应停在初始断点，CPU 窗口显示主模块/当前 RIP，F2 可下断点。
- 断点命中后 `[pseudo] wait event code=1 ... addr=断点地址`，x64dbg 暂停在正确地址。

## 8. 2026-08-27 22:00 追加：VM 实测日志定位到两个新根因

### 根因 1：PEB 物理直读失败 → lpBaseOfImage=0 → 无代码

实测日志出现 `snapshot imageBase read FAILED peb=...`，即 `NpMemAccessRead`
走手工页表物理直读时读不到目标 PEB（页表帧/页不在可读状态），导致
CREATE_PROCESS 的 `lpBaseOfImage=0`，x64dbg `ModLoad` 失败、模块表空白。

修复：`NpMemAccessRead` 在物理直读失败且 IRQL < DISPATCH 时，降级用
`MmCopyVirtualMemory` 跨进程读取整段（不调用任何 Nt*/句柄 API）。快照里的
镜像基址、PEB.Ldr 模块链表、映像路径全部走该兜底。

### 根因 2：prochide 只看进程名，且 GUI 未联动

“调试隐藏”与“进程隐藏”是两个独立开关；且 prochide 只按进程名后缀匹配，
对改名调试器无效。已做两处修复：

- `NpHvCtl` 点“调试隐藏 开”时自动启用 prochide（关时一起关）；
- `NpProcessHide` 新增按 PID 隐藏：DAP 拦截到真实调试器 PID 后自动登记，
  分离时移除；`FilterProcessList` 同时匹配 PID 与进程名，并新增
  `[prochide] hide entry pid=...` 日志用于复测确认。

### 根因 3（决定性）：MmCopyVirtualMemory PreviousMode 用错

`NpMemAccessCopyFromUser/CopyToUser` 原先传 `UserMode`，而调用方一侧是
内核缓冲（Wait 超时参数、DEBUG_EVENT 输出、QSI 过滤缓冲）。`UserMode`
按用户地址探测内核缓冲 → 全部返回 STATUS_ACCESS_VIOLATION：
- x64dbg 的 `NtWaitForDebugEvent` 每次都卡在超时参数拷贝；
- DEBUG_EVENT 永远写不回 x64dbg → 看不到代码；
- QSI 过滤写不回用户缓冲 → 任务管理器仍看到 x64dbg。

修复：两处 `MmCopyVirtualMemory` 改 `KernelMode`（源/目标由调用方保证，
缺页由内存管理器内部处理）。此修复同时打通 Wait 事件流与 prochide 过滤。
