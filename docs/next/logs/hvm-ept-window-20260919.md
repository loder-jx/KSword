# EPT 恒等映射窗口：从 8 TiB 到 32 TiB

issue #198，2026-09-19。

## 报的是什么，真的是什么

一位用户在 Intel Core Ultra 270K Plus 上启动常驻，界面说**「处理器不支持」**。

真因与处理器无关。链条是四段，每一段单独看都对：

1. `KSW_HVM_MAX_PML4_ENTRIES = 16` —— 身份映射窗口 8 TiB。这个数是在手边每台
   机器都报 39 或 42 位物理地址宽度的时候定的。
2. 这台机器 `CPUID.80000008H:EAX[7:0] = 45`，即 **32 TiB**。构建器按设计把映射
   截断到窗口，并置 `EPT_TRUNCATED`。
3. `hvm_resident.c` 见到 `EPT_TRUNCATED` 就拒绝进 VMX，返回 `STATUS_NOT_SUPPORTED`。
4. `KswordARKHvmControlStatusFromNtStatus` 把 `STATUS_NOT_SUPPORTED` 翻成
   `UNSUPPORTED_CPU`，界面显示「处理器不支持」。

于是一台**每一项能力都齐备**的处理器被告知自己不被支持，用户只能去查 CPU 与
BIOS —— 而那两处都没有问题。报告人最后是自己往 `KswordARKHvmBuildEptLocked`
里加了一行 `DbgPrintEx` 才挖出来的，打印的正是上面第 2 段那三个数。

两个缺陷，分开修：**窗口太小**是一个，**报错在说一件没发生的事**是另一个。
后者比前者更值得修：把常量调大只救这一台机器，让错误码说实话能救以后每一台。

## 修法

### 窗口

`KSW_HVM_MAX_PML4_ENTRIES` 16 → **64**（32 TiB，正好盖住 MAXPHYADDR ≤ 45）。

**刻意不取更大的值。** 报 46 位的机器现在会拿到一条说得出具体数字的拒绝
（见下），而不是被赖到处理器头上；为一台没人量过的机器提前把这个数调大，正是
当初那个 16 的来历。

### 代价：1 GiB 叶

直接把 16 改成 64 是能跑的，代价是每台机器在 prepare 时多花 128 MiB 非分页内存
与一千六百万次循环 —— 因为原来的构建循环对整个窗口逐 2 MiB 建叶，每 GiB 一个
页目录。而那个代价，正是当初 16 这个值的成因。

所以构建循环改成按 GiB 走，用一个问题决定粒度：**这一 GiB 里有没有已装 RAM？**

- **有** → 一个页目录、512 个 2 MiB 叶。RAM 叶按 MTRR 定型，而且规则、分离视图
  与内存监视都是从 PDE 往下拆到 4 KiB 的，2 MiB 是后端其余部分赖以工作的粒度。
- **没有** → 一个 1 GiB PDPT 叶，UC。MMIO 与保留区本来就统一 UC，512 个 2 MiB UC
  叶和一个 1 GiB UC 叶翻译结果完全相同，差别只是一个页目录。

需要 `IA32_VMX_EPT_VPID_CAP` bit 17。没有这一位时就是原来那条路径，页目录预算
（`KSW_HVM_MAX_EPT_PD_PAGES`，8192）此时真的会绑住，那时照样如实回报而不是静默
截断。实践上不会走到：1 GiB EPT 叶从 Haswell 就有，而 45 位宽度是近几年的事。

> 顺带：`eptLargePageEntries`（2 MiB 叶数）从此**不覆盖整个窗口**。权威的覆盖
> 范围是 `highestMappedPhysicalAddress`。界面与命令行都加了这句话，因为拿叶数
> 乘 2 MiB 去对账会得出"映射不全"这个错误结论。

### 错误码

新增 `KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL`（28）。

`hvm_resident.c` 的那处拒绝改回 `STATUS_SECTION_TOO_BIG` —— 名字是字面意思：
要映射的区域比我们能映射的大。它在翻译表里排在 `STATUS_NOT_SUPPORTED` **之前**，
也不会落到"START_RESIDENT 的兜底 = RENDEZVOUS_FAILED"上（那会更糟：一次根本没
走到会合的拒绝被报成会合失败）。

界面要说出三个数，缺一不可：

| 数 | 从哪来 |
| --- | --- |
| 本机需要多少位 / 多少个 PML4 项 | 界面**自己**执行 `CPUID.80000008H`。这是 CPL3 就能执行的指令，不需要驱动配合——而这条消息恰恰是在驱动已经拒绝之后才需要的 |
| 这一版驱动的窗口是多少 | 控制响应新增 `eptPml4EntryBudget`（占用原 `reserved2` 槽位，结构大小与协议版本都不动）。**不能**用界面自己编译时的常量：版本不齐时那个值正好是错的，而恰恰是版本不齐时这条消息最需要准确 |
| 换算成的地址空间大小 | 前两个数对普通用户没有意义 |

`eptPml4EntryBudget` **每次控制调用都填**，不只在失败时填：一个只在出事时才有
值的字段，没出事的时候没有任何地方能确认它是对的。

## 实测（2-vCPU 嵌套 Hyper-V 靶机）

驱动 `SHA256 = 973CFE99A0203D67EFF16C6F77D0F2C412F4BC6B2E2644E568B4EBF02978564A`，
来宾侧重算一致。

`prepare` 之后：

| 读数 | 值 |
| --- | --- |
| `highestMappedPhysicalAddress` | `0x80_0000_0000` = **512 GiB**（来宾 MAXPHYADDR = 39 位） |
| `eptPml4EntryBudget` | **64**（32 TiB 窗口） |
| `eptPml4Entries` | 1 |
| `eptPdptEntries` | **512**（512 个 GiB 槽位全部填满） |
| `eptLargePageEntries` | 4608 = 9 GiB 的 2 MiB 叶 |
| `eptPageCount` | **12** |
| `mappedRamMiB` | 8190 |

也就是：512 个 GiB 槽位里 **9 个是页目录**（覆盖 8 GiB RAM 加低端 MMIO），
**503 个是 1 GiB 叶**，整张表一共 **12 页**。

同一台机器上按旧写法是 1 + 1 + 512 = **514 页**、262144 次循环；报告人那台
45 位的机器按旧写法需要 32768 个页目录（128 MiB），而实际结果是直接被拒绝。

功能没有被改坏，九条自检全部重跑：

| 命令 | 判定 |
| --- | --- |
| `watch-selftest`（写） | PASS |
| `watch-selftest-read` | PASS |
| `watch-selftest-exec` | PASS |
| `watch-selftest-smp` | PASS |
| `watch-selftest-remap` | PASS |
| `watch-selftest-evidence` | PASS |
| `watch-selftest-restart` | PASS |
| `watch-selftest-process` | PASS |
| `watch-selftest-conflict` | PASS |

`watch-selftest-conflict` 会先 `teardown` 再用 EPTP 切换后端重新 `prepare`，
所以构建器在两种后端下各建了一次。全程无蓝屏（来宾 `MEMORY.DMP` 仍是 09-15
的旧文件），收尾已 `stop` + `teardown` + 卸载驱动 + 关机。

## 没有验到的

**`EPT_WINDOW_TOO_SMALL` 这条路径本身在这台靶机上问不出来**：来宾 MAXPHYADDR
是 39 位，32 TiB 的窗口绰绰有余，截断条件不成立。要证明这条消息真的会出现，
需要一台 MAXPHYADDR > 45 的机器，或者临时把窗口改小重编一次——后者验的是
"我把常量改小之后会不会报这个码"，不是"真实机器上会不会"，价值有限。

所以这一条按**静态判据**交付：拒绝点、NTSTATUS、翻译表与界面文案四处在同一次
改动里对齐，且翻译表里这一条排在 `NOT_SUPPORTED` 与命令兜底之前。

界面那段文案也没有人工点过——本轮 Qt 主程序编译被另一条并行工作（DDMA）的
在途改动挡住了，见提交说明。
