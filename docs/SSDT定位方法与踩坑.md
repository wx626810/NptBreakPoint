# Win11 内核 Nt* 函数地址定位：SSDT 解析方法与踩坑记录

> 场景：Windows 11 24H2+（含第三方 hypervisor 环境）将 `NtWriteVirtualMemory` 等
> 未文档化 Nt*/Zw* API 移出 ntoskrnl 导出表，且 SSDT 表被部分 hook 时，
> 如何可靠地拿到这些函数的真实地址（只读 SSDT，不改任何字节，PatchGuard 无感）。

- 日期：2026-08-19
- 验证环境：Win11（AnyHypervisorPresent=1，存在第三方 hypervisor），SSDT 被部分修改
- 结论：**三级解析（Mm 导出 → Zw 别名 → SSDT）** + **表特征扫描（抗 hook）** 实测闭环，
  `dbg hide on` 5/5 hooks 全部成功。

---

## 1. 为什么需要 SSDT

在标准 Windows 上，`MmGetSystemRoutineAddress("NtWriteVirtualMemory")` 必然成功。
但从 Win11 24H2 起（部分系统更早），微软将一批未文档化 Nt*/Zw* 移出导出表：

```
[dbghide] resolve 'NtWriteVirtualMemory': not exported (Nt/Zw)
```

此时只剩一条可靠路径：**SSDT（KiServiceTable）**——用 syscall 号索引服务表拿函数地址。
**注意**：这只是"读"SSDT 定位地址，不是"改"SSDT。改 SSDT 会被 PatchGuard 周期性校验
检测（bugcheck 0x109）；读不影响任何字节，完全安全。

---

## 2. 总体流程（三级解析）

```
NtWriteVirtualMemory
 ① MmGetSystemRoutineAddress("NtXxx")     → 导出表（Win10/旧版走这条）
 ② MmGetSystemRoutineAddress("ZwXxx")     → Zw 别名（部分系统只留其一）
 ③ SSDT：
    a. 从 ntdll 导出 stub 提取 syscall 号（mov eax, imm32）
    b. 定位 KiServiceTable（双锚点 + 表特征扫描）
    c. 函数地址 = 模块基址 + (LONG)条目   ← 4B 偏移表语义
```

---

## 3. 方法详解

### 3.1 提取 syscall 号（从 ntdll）

```c
// 当前进程 PEB → Ldr(0x18) → InLoadOrderModuleList(0x10) → 找 ntdll.dll
// ntdll 导出表找 NtXxx → stub 开头 0x40 字节内找 B8 imm32（mov eax, syscall#）
// 实测：QIP=0x19、QSI=0x36、WVM=0x3A、RVM=0x3F、DAP=0xD6、SCT=0x19A、PVM=0x50、CTE=0xC9
```

### 3.2 定位 KiServiceTable（核心）

**前提**：至少一个仍导出的、有已知 syscall# 的函数做锚点（首选 `NtQueryInformationProcess`，
几乎所有系统都保留导出）。

**第一步：定位 ntoskrnl 基址**
- 从锚点地址（如 QIP）向下按 64KB 对齐找 `MZ` 头
- **不能只查 2 字节 0x5A4D**——ntoskrnl 映像内部 .data 的 64KB 对齐位置可能恰好是 'MZ'
  （实测误命中 0xfffff800e31d0000）。必须做**完整 PE32+ 校验**：
  - `e_lfanew` 合理（0~0x1000）
  - `'PE'` 签名（0x4550）
  - OptionalHeader.Magic == `0x20B`（PE32+）
  - `SizeOfImage` ∈ 1MB~256MB
  - **必须包含锚点地址**（QIP 在 [Base, Base+Size] 内）——最强约束

**第二步：双锚点精确扫描**（标准环境）
```
已知：QIP(syscall#=0x19, 地址=0xFFFFF800E39AB830)、QSI(syscall#=0x36, 地址=...)
8B 表（老版本）：X + 0x19*8 == QIP 且 X + 0x36*8 == QSI  → X 是表
4B 表（1903+）：X + 0x19*4 处条目 == QIP_RVA 且同理 QSI → X 是表
```

**第三步：表特征验证（抗 SSDT hook，关键）**
```
若双锚点失效（SSDT 条目被 hook 修改），改用结构识别：
收集"QIP_RVA 作为 4B 值"在映像内出现的所有位置，
对每个位置检查连续 64 个条目是否都是合法 RVA（0x1000 ~ SizeOfImage）
→ 是则命中。SSDT 是 ~2000 个连续 4B RVA 的密集表，误命中率≈0；
即使部分条目被 hook（如 QSI），其余仍是 RVA，照样识别。
```

### 3.3 读条目（4B 表语义）

```c
// 实测验证：4B 条目 = 模块基址 + (LONG)条目（RVA 风格），不是表基址 + 条目！
// 验证方法：QIP 条目 = 0x9AB830；mz + 0x9AB830 == QIP 地址 ✅（闭环）
//          表基址 + 0x9AB830 != QIP ❌
函数地址 = ntoskrnl基址 + (LONG)SSDT[syscall]
```

---

## 4. 踩坑点（全部实测踩过）

| # | 坑 | 现象 | 修复 |
|---|---|---|---|
| 1 | **0x50 蓝屏：SEH 拦不住** | bugcheck 0x50 PAGE_FAULT_IN_NONPAGED_AREA，"cannot be protected by try-except" | 读前 **MmIsAddressValid 逐页预检**（SEH 只作二道） |
| 2 | **自写页表遍历在 hypervisor 环境误判** | 读用户态高地址失败（PML4 idx=0x7F 误判不 present），且自映射常量（0xFFFFF6FB7DBED000）在 LEGACY_PAGE_TABLE_ACCESS=1 时直接 0x50 | 改用内核 API **MmIsAddressValid** |
| 3 | **System 进程没有 ntdll** | DriverEntry 里 PEB 拿不到 ntdll → syscall#=N/A | **附加到用户进程**（KeStackAttachProcess + PsLookupProcessByProcessId） |
| 4 | **PEB 链表头传递错误** | 传 `*(Ldr+0x10)`（Flink）被当链表头再解引用 → **跳过第一个模块**（常是 ntdll） | 传**链表头节点地址** `ldr+0x10`，内部解引用 Flink |
| 5 | **ZwQuerySystemInformation 拿大小必然失败** | 首调传 NULL 返回 STATUS_INFO_LENGTH_MISMATCH，误当失败 → 进程枚举永远失败 | 把"预期失败"当正常，用 ReturnLength 扩缓冲重试（最多 4 次） |
| 6 | **MZ 搜索范围不够** | ntoskrnl 映像 ~10MB，锚点在其内部偏后；搜索下限 128MB 够不到基址 | 下限放宽 **256MB**（0x10000000） |
| 7 | **'MZ' 2 字节误命中** | 映像内部数据恰好 0x5A4D → PE 校验失败 → 扫描静默失败 | 完整 PE32+ 校验 + **MustContain 锚点** |
| 8 | **8B/4B 表基址语义错误** | 4B 条目用"表基址+条目"算 → 双锚点永不命中 | **模块基址 + 条目**（QIP 闭环验证） |
| 9 | **EntryIs4ByteOffset 未透传** | 命中 4B 表但默认走 8B 模式 → `TableBase + syscall*8` 索引错位，读出**相邻条目拼接值**（如 0x9E8EC009B05B8） | 表定位结果必须返回**条目格式**（4/8）并透传给读取 |
| 10 | **Nt/Zw 非别名** | 部分环境 Nt 与 Zw 地址不同（导出表重定向），Zw 兜底失效 | 按序尝试，**逐个验证**（QIP 字节 dump：标准序言 `push rbx...` 说明未重定向） |
| 11 | **SSDT 被 hook** | QSI 条目 ≠ QSI 导出地址；双锚点失效 | **表特征验证**（64 连续合法 RVA），不依赖条目==已知地址 |
| 12 | **LSTAR 反汇编扫描误命中** | KiSystemCall64 扫描找到的候选可能是 ntoskrnl 基址（PE 头字段碰巧满足） | 放弃该方案，改用**锚点/表特征扫描**（更鲁棒） |

---

## 5. 实测数据（2026-08-19）

```
SSDT: table=0xFFFFF800E3133470  mz=0xFFFFF800E3000000  kind=4 (4B RVA 表)
QIP 闭环验证：SSDT[0x19]=0x9AB830，mz+0x9AB830 == QIP 导出地址 ✅

函数                          syscall#    地址（SSDT 解析）
NtQueryInformationProcess     0x19        0xFFFFF800E39AB830  （== Mm 导出，闭环）
NtQuerySystemInformation      0x36        0xFFFFF800E309E900  （≠Mm，被 hook，预期内）
NtWriteVirtualMemory          0x3A        0xFFFFF800E39B060E
NtReadVirtualMemory           0x3F        0xFFFFF800E309E954
NtSetContextThread            0x19A       0xFFFFF800E39B962E
NtDebugActiveProcess          0xD6        0xFFFFF800E39B2680
NtProtectVirtualMemory        0x50        0xFFFFF800E39B0A01
NtCreateThreadEx              0xC9        0xFFFFF800E309F390

结果：dbg hide on → debug-hide enabled (5/5 hooks)
```

---

## 6. 与 PatchGuard / HVCI 的关系

- **读 SSDT 定位地址**：只读不改 → PG 无感（PG 校验的是"字节被改"）
- **Hook 方式**：用 NPT（嵌套页表）影子页重定向，**不修改任何 Guest 内存字节**
  → PG 的 CRC/哈希校验全部通过；HVCI 的代码页只读也不受影响（页表层操作）
- 结论：读 SSDT + NPT Hook 天生为 PG/HVCI 环境设计（见 `docs/调试器适配方案.md`）

---

## 7. 相关代码

- 验证驱动（隔离环境逐步诊断）：`tools/NtResolveProbe/NpProbe.cpp`（含全部 State 诊断）
- 主程序实现：`NptHook/services/NpDebugHide.cpp`
  - `NpDbgSafeReadBytes` / `NpDbgValidateImage` / `NpDbgFindSsdtByAnchorScan` /
    `NpDbgReadSsdtEntry` / `NpResolveViaSsdt`
- 完整功能：AMD NPT 无痕 Hook + X64DBG 无痕调试框架（NptBreakPoint 项目）
