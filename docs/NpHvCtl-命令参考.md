# NpHvCtl 命令参考（R3 管理工具）

> `NpHvCtl.exe` 是 NptBreakPoint 的 R3 控制工具，通过设备对象 `\\.\NpHv`
> 与内核驱动通信（协议见 `NptHook/include/NpIoctl.h`）。
> 需要管理员权限运行；驱动未加载时所有命令返回"打开设备失败"。
>
> 编译：`build_ctl.bat`（一键，输出 `output\NpHvCtl.exe`）
> 或手动：`g++ -O2 -I../NptHook/include NpHvCtl.cpp -o ../output/NpHvCtl.exe`（MinGW）

---

## 1. 基础命令

### `status` — 查询状态
```
NpHvCtl status
```
输出：协议版本、Hypervisor 是否运行、CPU 数、活动 Hook 数、驱动自隐藏状态。
```text
NptHook protocol v1
hypervisor    : yes
processors    : 8
active hooks  : 0
driver self-hide: disabled
```

### `hook <name|addr> <action> [ret]` — 安装 NPT 无痕 Hook
| 参数 | 说明 |
|------|------|
| `name` | 导出内核函数名（如 `NtQuerySystemInformation`）|
| `addr` | 内核地址（`0xfffff800...`）|
| `action` | `log`（记录调用并放行）/ `ret`（拦截，返回指定值）/ `pass`（放行）/ `code`（执行 R3 注入的位置无关机器码）|
| `ret` | `ret` 动作的返回值 |

```bat
NpHvCtl hook NtQuerySystemInformation log
NpHvCtl hook 0xfffff80012345678 ret 0
NpHvCtl hook NtQuerySystemInformation code   :: 注入演示机器码（改返回值）
```

### `unhook <hookid>` / `unhookall` — 卸载 Hook
```bat
NpHvCtl unhook 1
NpHvCtl unhookall
```

### `unload` — 卸载 Hypervisor
```bat
NpHvCtl unload
```
含排空窗口（200ms），之后可 `sc stop NpHv`。

### `demo` — 演示序列（默认命令）
安装 LogOnly Hook 到 NtQuerySystemInformation → 调用 5 次 → 查状态 → 卸载。

---

## 2. NPT 无痕断点

> 断点不修改任何 Guest 字节：读内存永远是原始指令，只有取指才触发。

### `bp <name|addr> [halt] [oneshot]` — 安装断点
| 标志 | 行为 |
|------|------|
| （无，默认）| 自动单步：命中→记录现场→单步执行原指令→重新布点（持续）|
| `halt` | 暂停模式：命中后钉住该线程，需 `bpcont` 继续 |
| `oneshot` | 单次模式：命中一次后自动解除 |

```bat
NpHvCtl bp NtQuerySystemInformation            :: 自动单步断点（持续）
NpHvCtl bp 0xfffff80012345678 halt oneshot    :: 暂停 + 单次
NpHvCtl bp NtCreateProcessEx halt
```
> 用户态地址断点需经 `dbg hide on` 下的 0xCC 拦截自动创建（见 §6）。

### `bplist` — 列出断点
```
NpHvCtl bplist
```
输出：id、模式（STEP/HALT）、地址、命中次数、是否暂停、最近命中 CPU/CR3。
```text
breakpoints: 2 active (total 2)
  #1  STEP addr=0xFFFFF80012345678 hit=42 cpu=2 cr3=0x000000001A2B3C40
  #2  HALT addr=0xFFFFF80098765432 hit=1 [halted] cpu=5 cr3=...
```

### `bpcont <id|all>` — 继续被暂停的断点（HALT 模式）
```bat
NpHvCtl bpcont 2
NpHvCtl bpcont all
```

### `bpdel <id>` — 卸载断点
```bat
NpHvCtl bpdel 1
```

---

## 3. NPT 监视（模拟硬件断点）

> 撤销目标页 R/W 位，数据访问触发 #NPF 记录，不占 DR0-DR3。
> AMD 限制：读监视（清 R 位）会同时拦截取指。

### `mon <name|addr> <r|w|rw>` — 安装数据访问监视
```bat
NpHvCtl mon NtQuerySystemInformation rw       :: 读写都监视
NpHvCtl mon 0xfffff80012345678 w              :: 只监视写
```

### `mondel <id>` — 卸载监视
```bat
NpHvCtl mondel 1
```

---

## 4. DR 硬件断点虚拟化（drprobe）

> 调试器（X64DBG）写 DR0-3/DR7 → SVM 拦截 → 记录假 DR + 解析断点地址；
> 读 DR → 回显假 DR（调试器以为断点生效）。

### `drprobe on|off` — 开关 DR 拦截
```bat
NpHvCtl drprobe on
NpHvCtl drprobe off
```
> 默认关闭（零性能开销）；开启期间每次线程切换多若干 VMEXIT，仅调试会话开启。

### `drstate` — 查询假 DR 与调试器设的硬件断点
```
NpHvCtl drstate
```
输出：drprobe 状态、假 DR0-3/DR6/DR7、pending 硬件断点列表（地址+类型）。
```text
drprobe: enabled
  fake DR0=0x0000000000000000 DR1=0x0000000000000000 ...
  pending hardware breakpoints: 1
    [0] addr=0x00007FF6A1C01000 type=execute
```

---

## 5. 无痕内存读写

### `mem <pid> <addr> <len>` — 物理直读目标进程内存
```bat
NpHvCtl mem 1234 0x7FF6A1C01000 64
```
输出：hex dump（最多 0x1000 字节/次）。目标页必须驻留物理内存（分页页返回
STATUS_NOT_FOUND）。

---

## 6. X64DBG 调试链路隐藏

> 开启后 Hook NtQueryInformationProcess / NtWriteVirtualMemory /
> NtReadVirtualMemory：调试检测查询返回假值、写 0xCC 自动转 NPT 断点、
> 读内存物理直读。只对"受保护进程"生效。

### `dbg hide on|off` — 开关调试隐藏
```bat
NpHvCtl dbg hide on
NpHvCtl dbg hide off
```

### `dbg protect <pid>` / `dbg unprotect <pid>` — 注册调试目标
```bat
NpHvCtl dbg protect 1234
NpHvCtl dbg unprotect 1234
```

### `dbg mode white|black` — 隐藏范围模式
```bat
NpHvCtl dbg mode white     :: 白名单（默认）：仅注册 PID 隐藏
NpHvCtl dbg mode black     :: 黑名单：除注册 PID 外，所有进程都隐藏
```

**X64DBG 完整会话示例**：
```bat
NpHvCtl drprobe on
NpHvCtl dbg hide on
NpHvCtl dbg protect 1234
:: 在 X64DBG 中 F2 下断点 → 自动转 NPT 无痕断点
NpHvCtl bplist                               :: 查看断点与命中
NpHvCtl drstate                              :: 查看硬件断点接管
NpHvCtl dbg hide off
NpHvCtl drprobe off
```

---

## 7. 常见错误码

| 状态码 | 含义 | 常见原因 |
|--------|------|----------|
| `0xC000000D` | STATUS_INVALID_PARAMETER | 地址/参数非法 |
| `0xC0000004` | STATUS_NOT_FOUND | 目标函数名解析失败 / 断点 id 不存在 |
| `0xC0000023` | STATUS_BUFFER_TOO_SMALL | 输出缓冲过小（协议不匹配）|
| `0xC00001A0` | STATUS_REVISION_MISMATCH | R3/R0 协议版本不一致（驱动需重载）|
| `0xC00000BB` | STATUS_NOT_SUPPORTED | 虚拟化未运行 |
| `0xC000009A` | STATUS_INSUFFICIENT_RESOURCES | 槽位耗尽（断点/监视/PID 表满）|
| 驱动未加载 | CreateFile 失败 | 先 `sc start NpHv` |
