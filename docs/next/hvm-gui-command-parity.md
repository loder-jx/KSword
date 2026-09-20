# HVM GUI 与命令行的分工

## 2026-09-19：主程序不再依赖 hvm_ctl

`hvm_ctl` 是功能测试探针，不是发布物。它此前以一种很隐蔽的方式进了主程序：
主程序自己带着 `--ksword-hvm-command` 这个无界面入口，而 GUI 的「完整操作」
子页是**把主程序自己当子进程重新拉起来**再解析它的标准输出。于是探针的命令
目录、执行引擎和 66 条命令的全部文案都随主程序一起发布。

这一整条通路已经摘除：

| 原位置 | 现状 |
| --- | --- |
| `main.cpp` 的 `tryRunHvmCommandLine` | 删除，主程序没有命令行入口 |
| `ArkDriverClient/HvmCommandProcess.{h,cpp}` | 删除 |
| `UI/KvmCommandPanel.{h,cpp}`（「完整操作」子页） | 删除 |
| `ArkDriverClient/HvmCommandCatalog.{c,h}`、`HvmCommandEngine.c` | 移到 `tools/hvm_ctl/`，只由探针编译 |
| `Ksword5.1.vcxproj` 的 `AuditKswordHvmCommandCatalog` 目标 | 删除（目录不再进主程序，改由探针自己的门禁核对） |
| 标题栏右键菜单 / KvmDock / 内核 HVM 页的「KVM 完整命令面板」入口 | 删除 |
| 语言包里 175 条只服务于该面板与命令目录的词条 | 删除 |

判据是成品二进制，不是源码：`Ksword5.1.exe` 与随附的两个语言包里，
`ksword-hvm-command`、`hvm_ctl`、`nested-page-map`、`acl-probe`、
`resident-vmreadbench`、`完整命令面板` 等字符串的出现次数全部为 0。

`tools/hvm_ctl/hvm_ctl.exe` 不受影响，仍然 `#include` 同一份目录与引擎，
`tools/hvm_ctl/build.cmd` 一条命令即可重建。

## 摘除后能力去了哪里

命令目录里 66 条，绝大多数是探针（`*-probe`、`nested-selfvirt*`、`*-test`、
`launch-test-guest`、`resident-vmreadbench`、TinyCore 换页等），随探针一起留在
`hvm_ctl`，主程序里不再出现。

只有 **R-1 进程处置与注入** 是例外：它有自己的 IOCTL
（`IOCTL_KSWORD_ARK_HVM_PROCESS` / `IOCTL_KSWORD_ARK_HVM_INJECT`），驱动侧是
实现完整的生产路径，此前只是恰好没有原生 GUI 入口。所以它改写成了原生面板：

- `ksword::kvm` 门面新增 `listProcessDispositions` / `freezeProcess` /
  `terminateProcess` / `releaseProcessDisposition` / `releaseAllProcessDispositions`
  与 `listInjections` / `injectDll` / `releaseInjection` / `releaseAllInjections`，
  与视图 / MSR / CR 三组同一个形状：同一道写权限门、同一套状态码翻译、
  每次操作都回填整张表；
- `UI/KvmProcessDialog` 承载两张表与两组表单，冻结 / 结束 / 注入三项分别过
  `confirmDestructiveAction`；
- 入口有两个：KvmDock 第 2 步分组里的「R-1 进程处置与注入...」，以及标题栏
  KVM 右键菜单里的同名项。

`inject-test`（向标记地址写常数）没有跟过来——它是测试用的写入，不是能力。

## 虚拟化 Tab 的结构

子页从五个减到四个：**跑第三方虚拟机 / 控制 / 状态详情 / 硬件虚拟化证据**，
默认落在「控制」。「硬件虚拟化证据」这个名字取代了原来的「VT-x/EPT 证据」：
同一页在 AMD 机器上显示的是 SVM/NPT 的读数，页名钉死在一套架构上会让另一套
的用户以为这页与自己无关。第 1 步分组里多了一个「硬件虚拟化证据」按钮，
把那一页从"翻到最后一个 Tab 才找得到"提到主线上。

后端分流的做法是**同一套界面，缺的项灰掉并说明原因**，不是两套界面：

- 灰掉的一组是隐蔽 Hook、EPT 分离视图、执行域、MSR 策略、CR 策略、
  R-1 进程处置与注入。它们的共同点不是"AMD 做不到"，而是全都建立在 EPT
  分离视图或 VMCS 字段上，而 SVM/NPT 后端目前做到的是资源准备、逐核 VMRUN
  自检与常驻；
- 不灰的是 R-1 内存操作与事件流：它们走物理内存窗口与事件环，与后端无关；
- **右键菜单里那批开关不跟着灰**。其中私有 EPT 与 EPTP 切换是持久化的，用户
  很可能是在另一台 Intel 机器上打开的，而 AMD 下它们开着会挡住准备资源——
  一起灰掉就把唯一的关闭入口也关上了。内核 HVM 页那两个被挡住的按钮现在
  逐条点名是哪几个开关开着，并指向右键菜单。

同一个判据（`KvmState::backend`）由 KvmDock、标题栏菜单、内核 HVM 页共用。
以前这三处各自去翻 QUERY 响应，代价不是麻烦而是不一致。

顺带修掉的三处 AMD 显示缺陷：

- 摘要横幅原先整块塞的是 `buildDetail` 的七行输出，而下方详情框显示的就是
  同一个 `buildDetail`——同样内容在一页上出现两次，其中一次还把横幅撑成七行；
- 逐 CPU 表的「来宾 / VM-exit」列在 AMD 下无条件显示 `0x0000000000000000`。
  没跑过 VMRUN 时那个字段就是零，而零是一个合法的退出码（#DE）：这是把一个
  从未采集过的值摆成硬件读数。改成 `vmExitCount == 0` 时显示 `-`；
- 「执行状态」列在 AMD 下是一个裸的阶段序号。改成名字，未知序号保留数字而不
  折成「未知」——新驱动加了阶段而界面没跟上时，那个数字是唯一的排查起点。

「跑第三方虚拟机」页的五步全部建立在 Intel 的嵌套 VMX 派发上，AMD 下按了不会
有任何效果。这一页现在按后端把五步标成「不适用」并说明原因，只留「刷新」可用。

## hvm_ctl 自己

```text
hvm_ctl.c ──#include──→ HvmCommandCatalog.c + HvmCommandEngine.c ──→ 共享驱动协议
```

三份都在 `tools/hvm_ctl/` 下。`audit_catalog.py` 仍是构建门禁，但只核对目录
自洽性（命令名唯一、每条命令都有派发分支）；它原先还断言 GUI 语言包里存在
对应词条，那条断言的前提是目录被主程序消费，已随依赖一起去掉。

参数校验不打开驱动，可在开发机运行：

```powershell
.\tools\hvm_ctl\build.cmd
.\tools\hvm_ctl\hvm_ctl.exe --json commands
.\tools\hvm_ctl\hvm_ctl.exe --json --validate nested-page-map 1234501e 7000000 d1
python tools\hvm_ctl\audit_catalog.py
python tools\hvm_ctl\test_command_parity.py
```

## 历史记录

摘除之前这条通路做过的修复与实测，留档备查：

- `gdt-dump`、`msr-log` 不再从固定 argv[2] 读取参数，`--json` 不影响参数位置；
- 数值统一校验进制、位宽、完整输入与页对齐；拒绝溢出、负数、垃圾后缀及额外参数；
- `resident-vmreadbench` 默认次数明确为 512，时长默认 1000 毫秒；
- DLL 路径由 Windows Unicode 参数统一转换为 UTF-8，再转换为驱动的 UTF-16；
- 退出码 0、1、2、3 分别表示完成、传输失败、拒绝/无效、未实际验证。

2026-09-16 曾有一条 GUI 表单覆盖测试（主程序上挂 `--ksword-hvm-gui-test`），
当天整条删除——它是塞在产品 `main()` 里的自检开关，而且每条命令等最多 30 秒，
整轮跑不完，实测 180 秒不返回只能强杀。今天摘掉的 `--ksword-hvm-command`
是同一类东西的最后一个：产品的入口不是测试入口。

[TinyCore 实测](logs/hvm-gui-live-effect-20260915.txt)在 EPT12 `0x1CAC605E`
的专用 GPA `0x07000000` 上完成 `A5 → 换页读到 D1 → 影子页写入 B2 → 撤销读回 A5`，
结束时 `active=0`、`retired=0`，原页恢复。该路径现在只能经 `hvm_ctl` 走。
真实 TinyCore 内存效果的边界与日志见[单页 EPT 控制](nested-ept-page-control.md)。

## hvm_ctl 命令目录

下表是探针自己的参考，不再对应任何 GUI 入口。

| 分类 | 命令名 | CLI 命令 | 访问 | 参数 |
| --- | --- | --- | --- | --- |
| 生命周期 | 准备 AMD 嵌套探针 | `prepare-svm-probe` | 写 | 无 |
| 生命周期 | AMD 嵌套 VMRUN 自检 | `self-test-svm-nested` | 写 | 无 |
| 查询与观测 | 虚拟化测量 | `metrics` | 只读 | 无 |
| 查询与观测 | 运行状态 | `status` | 只读 | 无 |
| 查询与观测 | CPUID 可见性 | `cpuid-view` | 只读 | 无 |
| 查询与观测 | 平台探针 | `probe-platform` | 只读 | 无 |
| 查询与观测 | 使用前自检 | `selfcheck` | 只读 | 无 |
| 查询与观测 | GDT 快照 | `gdt-dump` | 只读 | 处理器编号（十进制）（十进制 32 位，默认 `0`） |
| 查询与观测 | 事件记录 | `events` | 只读 | 起始事件序号（十进制）（十进制 64 位，默认 `0`）；最多事件数（十进制）（十进制 32 位，默认 `64`） |
| 查询与观测 | EPT 叶项 | `ept-leaf` | 只读 | 物理地址（十六进制）（十六进制 64 位，默认 `0`） |
| 生命周期 | 准备资源 | `prepare` | 写 | 无 |
| 生命周期 | 准备 EPTP 切换后端 | `prepare-eptpsw` | 写 | 无 |
| 生命周期 | 准备每核私有 EPT | `prepare-localept` | 写 | 无 |
| 生命周期 | 处理器虚拟化自检 | `self-test` | 写 | 无 |
| 生命周期 | 启动常驻 | `resident` | 写 | 无 |
| 生命周期 | 启动嵌套常驻 | `resident-nested` | 写 | 无 |
| 生命周期 | 启动嵌套常驻并隐藏身份 | `resident-nested-hidehv` | 写 | 无 |
| 生命周期 | 嵌套常驻完整快照对照 | `resident-nested-fullsnapshot` | 写 | 无 |
| 生命周期 | VMREAD 开销测量 | `resident-vmreadbench` | 写 | VMREAD 次数（十进制）（十进制 32 位，默认 `512`） |
| 生命周期 | 启动常驻并记录退出 | `resident-trace` | 写 | 无 |
| 生命周期 | 有界常驻自检 | `soak` | 写 | 保持时长（毫秒）（十进制 32 位，默认 `1000`） |
| 生命周期 | 停止常驻 | `stop` | 写 | 无 |
| 生命周期 | 释放资源 | `teardown` | 写 | 无 |
| 生命周期 | 重置故障 | `reset-fault` | 写 | 无 |
| 嵌套与诊断 | 一次性测试来宾 | `launch-test-guest` | 写 | 无 |
| 嵌套与诊断 | 嵌套能力校验 | `validate-nested` | 写 | 无 |
| 嵌套与诊断 | 单核嵌套探针 | `nested-probe` | 写 | 无 |
| 嵌套与诊断 | 全核嵌套探针 | `nested-probe-all` | 写 | 无 |
| 嵌套与诊断 | EPT A/D 拒绝探针 | `nested-ad` | 写 | 无 |
| 嵌套与诊断 | 单核自虚拟化探针 | `nested-selfvirt` | 写 | 无 |
| 嵌套与诊断 | 全核自虚拟化探针 | `nested-selfvirt-all` | 写 | 无 |
| 嵌套与诊断 | 设备访问位探针 | `acl-probe` | 写 | 无 |
| 嵌套与诊断 | 控制标志拒绝探针 | `probe-flags` | 写 | 无 |
| 嵌套与诊断 | 仅执行权限探针 | `probe-xonly` | 写 | 无 |
| 嵌套与诊断 | 单次放行规则探针 | `rule-allowonce` | 写 | 无 |
| 嵌套与诊断 | 跨核 TLB 探针 | `tlb-probe` | 写 | 保持时长（毫秒）（十进制 32 位，默认 `1000`） |
| 嵌套与诊断 | 强制退出 TLB 探针 | `tlb-probe-exit` | 写 | 保持时长（毫秒）（十进制 32 位，默认 `1000`） |
| EPT 视图 | 查询分离视图 | `view-query` | 只读 | 无 |
| EPT 视图 | 视图安装探针 | `view-probe` | 写 | 无 |
| EPT 视图 | 视图效果验证 | `view-effect` | 写 | 无 |
| EPT 视图 | 验证现有视图 | `view-verify` | 写 | 无 |
| TinyCore 换页 | 查询嵌套页映射 | `nested-page-query` | 只读 | 无 |
| TinyCore 换页 | 替换 TinyCore 物理页 | `nested-page-map` | 写 | EPT12 指针（十六进制）（十六进制 64 位，必填）；来宾物理页（十六进制，4 KiB 对齐）（十六进制，4 KiB 对齐，必填）；影子页填充值（00–FF）（十六进制 00–FF，必填）；VMM 进程 PID（0 自动选择 VMware）（十进制 32 位，默认 `0`） |
| TinyCore 换页 | 替换整段物理区间 | `nested-page-map-region` | 写 | EPT12 指针（十六进制）（十六进制 64 位，必填）；来宾物理基址（十六进制，需按粒度对齐）（十六进制，4 KiB 对齐，必填）；叶粒度（12=4 KiB，21=2 MiB，30=1 GiB）（十进制 32 位，默认 `21`）；VMM 进程 PID（0 自动选择 VMware）（十进制 32 位，默认 `0`） |
| TinyCore 换页 | 扫描源表后替换区间 | `nested-page-map-region-scan` | 写 | EPT12 指针（十六进制）（十六进制 64 位，必填）；来宾物理基址（十六进制，需按粒度对齐）（十六进制，4 KiB 对齐，必填）；叶粒度（12=4 KiB，21=2 MiB，30=1 GiB）（十进制 32 位，默认 `21`）；VMM 进程 PID（0 自动选择 VMware）（十进制 32 位，默认 `0`） |
| TinyCore 换页 | 改写区间内一页 | `nested-page-stage` | 写 | 页索引（十进制，0 起）（十进制 32 位，必填）；填充值（00–FF）（十六进制 00–FF，必填） |
| TinyCore 换页 | 区间内容摘要 | `nested-page-digest` | 只读 | 无 |
| TinyCore 换页 | 撤销 TinyCore 换页 | `nested-page-remove` | 写 | 无 |
| TinyCore 换页 | 换页故障注入 | `nested-page-map-test` | 写 | EPT12 指针（十六进制）（十六进制 64 位，必填）；来宾物理页（十六进制，4 KiB 对齐）（十六进制，4 KiB 对齐，必填）；影子页填充值（00–FF）（十六进制 00–FF，必填）；故障阶段（1–4）（十进制 32 位，必填） |
| TinyCore 换页 | 撤销失效故障注入 | `nested-page-remove-test` | 写 | 无 |
| 寄存器策略 | 记录指定 MSR | `msr-log` | 写 | MSR 编号（十六进制）（十六进制 32 位，默认 `10`） |
| 寄存器策略 | 清空 MSR 策略 | `msr-clear` | 写 | 无 |
| 寄存器策略 | 开启 CR3 追踪 | `cr-track-cr3-on` | 写 | 无 |
| 寄存器策略 | 关闭 CR3 追踪 | `cr-track-cr3-off` | 写 | 无 |
| R-1 进程 | 查询注入 | `inject-query` | 只读 | 无 |
| R-1 进程 | 标记写入测试 | `inject-test` | 写 | 进程 PID（十进制）（十进制 32 位，必填）；执行靶页地址（十六进制）（十六进制 64 位，必填）；标记地址（十六进制）（十六进制 64 位，必填）；写入值（十六进制）（十六进制 32 位，默认 `4B535744`） |
| R-1 进程 | 注入 DLL | `inject-dll` | 写 | 进程 PID（十进制）（十进制 32 位，必填）；执行靶页地址（十六进制）（十六进制 64 位，必填）；LoadLibraryW 地址（十六进制，0 自动解析）（十六进制 64 位，必填）；DLL 完整路径（Unicode 路径，必填） |
| R-1 进程 | 撤销进程注入 | `inject-release` | 写 | 进程 PID（十进制）（十进制 32 位，必填） |
| R-1 进程 | 撤销全部注入 | `inject-release-all` | 写 | 无 |
| R-1 进程 | 查询进程处置 | `proc-query` | 只读 | 无 |
| R-1 进程 | 冻结进程 | `proc-freeze` | 写 | 进程 PID（十进制）（十进制 32 位，必填）；执行靶页地址（十六进制）（十六进制 64 位，必填） |
| R-1 进程 | 结束进程 | `proc-terminate` | 写 | 进程 PID（十进制）（十进制 32 位，必填）；执行靶页地址（十六进制）（十六进制 64 位，必填） |
| R-1 进程 | 撤销进程处置 | `proc-release` | 写 | 进程 PID（十进制）（十进制 32 位，必填） |
| R-1 进程 | 清空进程处置 | `proc-release-all` | 写 | 无 |
| 查询与观测 | 命令帮助 | `help` | 只读 | 无 |
| 查询与观测 | 命令目录 | `commands` | 只读 | 无 |
