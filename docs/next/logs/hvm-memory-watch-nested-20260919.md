# HVM 内存监视 · 嵌套 Hyper-V 靶机实测

issue #195 第二十二节验收，2026-09-19。

## 靶机

| 项 | 值 |
| --- | --- |
| 虚拟机 | `KSword-HVM-Target`（Hyper-V，宿主 Windows 11 Pro for Workstations 26300） |
| 来宾 | Windows 11 Pro，build 22621 |
| vCPU | **2**（按 issue 验收要求从 4 改为 2） |
| 内存 | 8 GiB，静态 |
| 嵌套 | `ExposeVirtualizationExtensions = True`，来宾 `HypervisorPresent = True` |
| testsigning | Yes |
| **Monitor Trap Flag** | **不可用**——驱动 selfcheck 原话：「没有（嵌套 Hyper-V 不向客户机通告它）」 |
| execute-only EPT | 可用（`IA32_VMX_EPT_VPID_CAP` bit0 置位） |

MTF 不可用这一条正是本功能存在的前提：`ALLOW_ONCE` 靠 monitor-trap 把权限收回来，
在这台机器上恒不可用；`WATCH_ONCE` 去掉了收回那一步，所以不需要它。

## 产物

签名走仓库自带的自签测试证书（`scripts\Sign-KswordArkDriverTest.ps1`，
`CN=KswordARK Test Signing Certificate`，指纹 `34E402E8…`），证书导入来宾的
`LocalMachine\Root` 与 `TrustedPublisher`。

> 期间发现 `.cert\KswordARK-TestSigning.cer` 与同目录 `.pfx` **不是同一张证书**
> （`.cer` 是 `62FDA24A…`，`.pfx` 里是 `34E402E8…`，同主题不同代）。导入 `.cer`
> 不会为该签名建立信任，必须从 `.pfx` 导出配套公钥证书。这是仓库里一个既有的
> 陷阱，与本功能无关，但会让任何人的测试签名部署卡在"证书装了却还是不认"。

| 文件 | SHA-256 |
| --- | --- |
| `KswordARK.sys`（最终版） | `365A3341190C8AE7FA918BB1B34841B689813DD4FA39DCA6A66F97112E73AB5D` |
| `hvm_ctl.exe`（最终版） | `9C9FB91D1E2641D95A1622E1CACE4B0D3802100BA79F13CB27CA4B9A7BBBA8B2` |

每次部署都在来宾侧重算哈希与本地比对，确认跑的是刚构建的那一份而不是残留副本。

## 第 1 项 · WRITE First-touch

`hvm_ctl --json watch-selftest`，退出码 0，**PASS 13/13，失败 0，问不出来 0**。

```
watchId        2561
physicalPage   0x00000001FA31F000
residentBefore 2
residentAfter  2
```

| # | 检查 | 期望 | 实测 |
| --- | --- | --- | --- |
| 1 | 安装成功并分配非零编号 | `status=OK` 且 `watchId != 0` | `0xA01` |
| 2 | 实际生效掩码等于请求 | 写监视不触发架构归一化 | `0x2` |
| 3 | 武装后状态 | `armed` | `armed` |
| 4 | 装监视之前那次写不算命中 | `hitCount = 0` | `0` |
| 5 | 写触发一次命中 | `hitCount = 1` | `1` |
| 6 | 命中后自动解除 | `disarmed` | `disarmed` |
| 7 | 命中 GPA 落在被监视页 | `gpa & ~0xFFF` = 监视页 | `0x1FA31F000` |
| 8 | 命中现场记下非零 RIP | `rip != 0` | `0x00007FF7AC77A726` |
| 9 | 有效 GLA 指向实际被写地址 | `gla = &page[0]` | `0x00000227F0E10000` |
| 10 | 事件证据没有丢 | `lastHitStatus = published` | `published` |
| 11 | 第二次写不再命中 | `hitCount` 不变 | `1` |
| 12 | 被监视的写最终完成 | `page[0] = 0xB2` | `0xB2` |
| 13 | 命中没让任何处理器退出虚拟化 | `residentAfter = residentBefore` | `2 = 2` |

第 12、13 两条是这个功能与别的处置的分界：**命中不阻止访问**（与 `ENFORCE` 的
分界），**命中不结束常驻**（与严格 tripwire 的根本区别，也就是 issue 里那句
"命中 Watch ≠ HVM 退场"）。

## 第 4 项 · Nested Hyper-V（P0 关键验收项）

上表就是在这台 2-vCPU 嵌套靶机上跑出来的：

- 不依赖 Monitor Trap Flag —— 驱动明确报告本机没有它；
- WRITE First-touch 正常 Arm 并正常命中；
- `residentBefore = 2`，`residentAfter = 2`；
- 来宾不挂死（宿主侧全程 `State=Running / 正常运行`）；
- 不触发全局 fail-closed。

## 第 6 项 · 同页冲突（第一轮：watch vs watch）

同一物理页上已有一条 watch 时再装：

```
status=leaf-conflict  owner=watch#3841
```

明确拒绝，指名占用者，原有 watch 不变。**PASS**

这一轮问的是 §17 的后半句（"同一物理页上的多个 Watch 第一版也可以直接拒绝"）。
§22.6 问的是前半句——目标页已有 **CLOAK / HOOK** 视图——见下面第二轮。

## 第 8 项 · HVM restart（第一轮）

```
watchId=5889   装上=armed   常驻中=armed   停常驻后=invalidated
rearm status=ok  state=armed  hitCount=0
```

停止常驻后 watch 转 `invalidated` 而不是静默保持 `armed`——watch 是"某段时间里
有人在看"的断言，跨过一次没人看的空档还报"未命中"是编造的观测结果。显式
`watch-rearm` 后恢复 `armed`。**PASS**

## 实机揪出的四个缺陷

离线套件（157/157）一条都抓不到这四个，它们只有真机第一次调用才暴露：

1. **外层契约门的白名单没同步。** `KswordARKHvmEptRuleControl` 有一张 flags 与
   operation 的白名单，`WATCH_ONCE` / `REARM` / `WATCH_QUERY` 只加进了协议头和
   内层 `...Locked`，这道门没加 —— 每一条 watch 请求在到达处置逻辑之前就被判
   `STATUS_INVALID_PARAMETER`，用户侧只看到 `win32=87`。这道门没有宿主侧对应物，
   加多少离线断言都跑不到那一行。
2. **我给 watch 加的"必须已常驻"门与既有安全不变式互斥。** 规则表在整个常驻期间
   冻结（退出路径不取 PASSIVE 锁就扫它），所以 watch 根本装不上。修法不是削弱那条
   冻结 —— 它是真实的安全不变式 —— 而是去掉多余的门：watch 与其余 EPT 规则一样
   **常驻停着时装，启动常驻后生效**。
3. **冻结时回报的状态码在说一件没发生的事。** 原先复用 `PARTIAL`（"部分处理器未能
   完成失效"），而实际上一个字段都没改过，还把读者引向失效机制。改成
   `RESIDENT_FROZEN`，直说"先停常驻"。顺带把 `WATCH_QUERY` 从冻结与高危策略审计里
   豁免：读表必须能在常驻期间做，那正是命中会发生的整个窗口。
4. **自检自己越界崩了。** 用例数组写成 12，实际填 13 条，靶机上直接 `0xC0000005`。
   一个会自己崩掉的自检产出的是"没有读数"，不是"失败"。

另外记一次自己的假读数：验收第 8 项第一遍判成 FAIL，实际是我拿 JSON 里的字符串
`"invalidated"` 去和整数 `4` 比。功能一直是对的，错的是判据。

---

# 第二轮 · 剩余验收项（同日，同一台靶机）

第一轮之后补齐了 2 / 3 / 5 / 7 / 9，并把 6 / 8 换成可重复的自检命令重跑了一遍。
每一项都做成 `hvm_ctl` 的一条命令，退出码即判定（`0` PASS、`2` FAIL、`3` 有
"问不出来"的项但无失败），JSON 里带完整逐条读数。

本轮产物：

| 文件 | SHA-256 |
| --- | --- |
| `KswordARK.sys` | `A233203E169D4D26EF1480ACEB7614CFD6D4C291C575C00012F6DBBF4A12AE2F` |

来宾侧重算哈希与宿主一致。来宾 `featureNames` 里**没有** `MONITOR_TRAP_FLAG`
（有 `EPT_4KB_SPLIT` / `EPT_RULES` / `EPTP_LIST_READY` / `EPTP_SWITCH_ARMED`），
`eptExecuteOnly = true`。这是"这台机器没有 MTF"的直接读数，不是转述。

## 第 2 项 · READ First-touch

`hvm_ctl --json watch-selftest-read`，退出码 0，**PASS 13/13**。

```
watchId 2305   physicalPage 0x00000001E068B000   residentBefore 2   residentAfter 2
```

关键的一条是第 2 检查，它只在 READ 下成立：

| # | 检查 | 期望 | 实测 |
| --- | --- | --- | --- |
| 2 | 请求读时实际掩码必然连带写 | `effective ⊇ {R,W}` 且是 requested 的超集 | `0x3`（READ\|WRITE） |
| 12 | 被监视的读最终真的完成了 | 读回装监视前写下的 `0xA5` | `0xA5` |
| 13 | 命中没让任何处理器退出虚拟化 | `residentAfter = residentBefore` | `2 = 2` |

`requested = 0x1`、`effective = 0x3` 就是 issue 第五节要求界面并排显示两栏的
硬理由：EPT 不存在可写不可读的叶（SDM 31.3.3.1），所以"只监视读"在硬件上必然
连写也监视了。这一栏不是措辞谨慎，是实测数值。

## 第 3 项 · EXECUTE First-touch

`hvm_ctl --json watch-selftest-exec`，退出码 0，**PASS 13/13**。

```
watchId 3841   physicalPage 0x000000003F742000   residentBefore 2   residentAfter 2
```

页按 `PAGE_EXECUTE_READWRITE` 分配并写入一条 `0xC3`（`ret`），然后调用它。

| # | 检查 | 期望 | 实测 |
| --- | --- | --- | --- |
| 2 | 实际掩码等于请求 | 拒绝执行不需要 execute-only 能力，不该被放宽 | `0x4` |
| 8 | 命中现场记下非零 RIP | `rip != 0` | `0x000001D405330000` |
| 12 | 被监视的执行最终完成 | 两次调用都正常返回 | 返回了（`page[0]` 仍是 `0xC3`） |

第 8 条同时满足 §22.3 的"RIP 位于目标页"：`0x1D405330000` 就是被监视页的基址。

选 `ret` 而不是别的指令有理由：它是最短的合法函数，不碰任何寄存器，调回来之后
状态与调用前完全一样，于是"原执行最终正常完成"这条判据不会被别的副作用污染。

## 第 5 项 · SMP 同时命中

`hvm_ctl --json watch-selftest-smp`，退出码 0，**PASS 7/7**。

每个可用处理器绑一个线程（本机 2 个），全部报到后一起放行，同时写同一个被监视页。

| 检查 | 期望 | 实测 |
| --- | --- | --- |
| 全部线程都跑完，没有卡住 | `WaitForMultipleObjects` 不超时 | 不超时 |
| 每个处理器上的写都完成了 | `completed = 线程数` | `2` |
| **只有一个逻辑首命中** | `hitCount = 1` | `1` |
| 命中后自动解除 | `disarmed` | `disarmed` |
| 首命中记在一个具体处理器上 | 处理器号在参与集合内 | `0` |
| 所有被监视的写最终都落了盘 | 每个线程写下的字节都读得回 | `2/2` |
| 两个处理器都还在虚拟化里 | `residentAfter = residentBefore` | `2 = 2` |

`hitCount = 1` 是这一项的全部意义。多核竞争下"各算一次第一次"这个错误**没有
任何其它症状**：页恢复了、线程跑完了、机器没崩，只是同一个第一次被记了两遍。
它靠的是 `InterlockedCompareExchange(ARMED→TRIGGERED)`，而输掉的那个核也必须
修自己那份视图——否则它会在同一页上永远违规下去。

超时判 FAIL 而不是重试：这条路径没有任何理由需要秒级时间，超时就是死锁。

## 第 7 项 · VA 映射变化

`hvm_ctl --json watch-selftest-remap`，退出码 0，**PASS 5/5**。

```
armedPage   0x000000001D335000
currentPage 0x00000000C0838000
```

装完监视后把同一个虚拟地址解提交再提交，内存管理器换了一个页框。

| 检查 | 期望 | 实测 |
| --- | --- | --- |
| 监视仍绑定在装它时那个物理页上 | `physicalPage` = Arm 时的页 | `0x1D335000` |
| 监视如实报告它当初解析的那个虚拟地址 | `requestedAddress` = 原 VA | `0x17709E90000` |
| 当前 VA 已经指向另一个物理页 | 当前翻译 ≠ Arm 时的页 | `0xC0838000` |
| 重映射没有把监视状态改掉 | `armed` | `armed` |
| **写新映射不会命中原监视** | `hitCount` 仍为 0 | `0` |

要证的是"**没有**跟过去"。第一版不跟踪 VA 重映射是承诺而不是遗漏，所以这一项
的通过条件与直觉相反：命中了才是缺陷。界面用 `physicalPage` 与当前翻译的差值
检测这一情形并明说"这条监视仍盯着武装时那一页，不再对应该虚拟地址"。

## 第 9 项 · Event loss

`hvm_ctl --json watch-selftest-evidence`，退出码 0，**PASS 6/6**。

```
hitSequence 46   newestSequence 10779   droppedRows 2542
```

方法是用**环回绕**这条确定路径，而不是去制造并发丢包（那不可控）：开着
`TRACE_ROUTINE_EXITS` 起常驻，环每秒周转二十几次，命中那一行几十毫秒就被推出去。
表里同时留一条从没被碰过的监视作对照。

| 检查 | 期望 | 实测 |
| --- | --- | --- |
| 命中确实发生了 | `hitCount=1` 且 `disarmed` | `1 / disarmed` |
| 命中现场记在监视自己身上 | `rip`、`cr3` 非零 | `rip=0x7FF7DCB7B2B5` |
| 命中事件先是取得回来的 | 按序号能在环里找到 | 序号 46 找到 |
| **事件被挤掉之后仍能证明命中过** | `droppedRows != 0` 且按序号取不回 | `droppedRows=2542` |
| 事件没了，监视仍报得出命中过 | `hitCount=1` 且 `disarmed` | `1 / disarmed` |
| **与从没被碰过的监视读数不同** | 对照组 `hitCount=0` 且 `armed` | `0 / armed` |

最后一条是这一项真正的判据。只有两者读数不同，"区分得开"这句话才有证据——
否则一条全零的记录既能解释成"从未命中"，也能解释成"命中了但证据丢了"，而这两句
话给用户的结论正好相反。

## 第 6 项 · 视图冲突（第二轮，CLOAK 视图）

`hvm_ctl --json watch-selftest-conflict`，退出码 0，**PASS 6/6**。

```
viewId 1   physicalPage 0x000000011587C000
```

| 检查 | 期望 | 实测 |
| --- | --- | --- |
| 对照用的分离视图装上了 | `status=OK` 且 `viewId != 0` | `viewId=1` |
| 监视没装上 | `status = 10 (leaf-conflict)` | `10` |
| 说得清是谁占着这一页 | `ownerKind=1(view)` 且 `ownerId=该视图` | `1 / 1` |
| 被拒的监视没有留下编号 | `ruleId = 0` | `0` |
| 原视图还在，物理页没变 | 同一 `viewId` 指向同一页 | `0x11587C000` |
| **原视图的类型没被改掉** | `kind` 仍是 CLOAK | CLOAK |

后两条是这一项里最容易被漏掉、也最要紧的：一个"拒绝了但顺手把别人的叶项改了"
的实现，从返回值上看与正确实现**完全一样**，症状要等到那条视图下一次被用到时
才出现，而那时已经没人会把它与这次安装联系起来。

第一次跑这一项得到的是 `BLOCKED / view-add-refused / viewStatus=9`，原因在我
自己：安装分离视图要 EPTP 切换后端，而后端是在 `prepare` 那一刻定下的；资源已经
准备过时再带新标志 `prepare` 回的是 `ALREADY_PREPARED`，不会重配。自检改成先
`teardown` 再 `prepare-eptpsw` 之后就装上了。**一个由自己造成的 BLOCKED 比 FAIL
更坏**——它会让人去查机器。

## 第 8 项 · HVM restart（第二轮，可重复版）

`hvm_ctl --json watch-selftest-restart`，退出码 0，**PASS 5/5**。

| 检查 | 期望 | 实测 |
| --- | --- | --- |
| 停常驻之后监视被标成已失效 | `invalidated` | `invalidated` |
| 下一次常驻不会静默恢复旧监视 | 仍 `invalidated` | `invalidated` |
| **失效的监视不再命中** | `hitCount` 仍为 0 | `0` |
| 显式重新武装之后回到 ARMED | `armed` | `armed` |
| 重新武装换了一个新的武装代次 | `armedGeneration` 变了 | `0x31` |

第三条是状态位与实际叶项之间的对账：状态说"失效"，而实际叶项若还装着，写它就会
命中。命中了就说明状态位在撒谎。

## P1 · CR3 → 进程归因

`hvm_ctl --json watch-selftest-process`，退出码 0，**PASS 4/4**。

```
hitCr3 0x000000014F3DB000   ownPid 10016   scanned 162
```

| 检查 | 期望 | 实测 |
| --- | --- | --- |
| 命中现场记下了非零的 CR3 | `cr3 != 0` | `0x14F3DB000` |
| 归因扫描真的跑起来了 | `scanned > 0` | `162` |
| **归出来的就是本进程** | `resolvedProcessId = GetCurrentProcessId()` | `10016 = 10016` |
| 问一个不存在的地址空间会干净地答没有 | `status=6(not-found)` 且 `pid=0` | `6 / 0` |

判据分两级是有意的：**归不出来是一条限制**（写进界面就行），**归到别的进程上
是假证据**（会把人引到错误目标上）。所以只有后者判 FAIL；前者判 BLOCKED 并把
扫描数摆出来，让人看得出是"扫过 162 个都不是它"而不是"一个都没扫成"。

驱动侧的判据是 attach 进目标进程读回 `CR3`，不读 `EPROCESS` 里任何字段——Windows
不公开 `DirectoryTableBase` 的稳定偏移，而读错字段的后果不是崩溃，是一个照样能
走页表、照样能给出物理地址的错值。

## 本轮汇总

| # | 验收项 | 判定 | 命令 |
| --- | --- | --- | --- |
| 1 | WRITE First-touch | **PASS 13/13** | `watch-selftest` |
| 2 | READ First-touch | **PASS 13/13** | `watch-selftest-read` |
| 3 | EXECUTE First-touch | **PASS 13/13** | `watch-selftest-exec` |
| 4 | Nested Hyper-V（P0 关键） | **PASS** | 上面每一条都跑在这台 2-vCPU 嵌套靶机上 |
| 5 | SMP 同时命中 | **PASS 7/7** | `watch-selftest-smp` |
| 6 | View 冲突 | **PASS 6/6** | `watch-selftest-conflict` |
| 7 | VA 映射变化 | **PASS 5/5** | `watch-selftest-remap` |
| 8 | HVM restart | **PASS 5/5** | `watch-selftest-restart` |
| 9 | Event loss | **PASS 6/6** | `watch-selftest-evidence` |
| P1 | CR3 → 进程归因 | **PASS 4/4** | `watch-selftest-process` |

全程无蓝屏（来宾 `C:\Windows\MEMORY.DMP` 仍是 09-15 的旧文件，本轮没有新转储），
来宾未挂死，收尾时已 `stop` + `teardown` + 卸载驱动 + 关机，只保留 `clean-install`
一个检查点。
