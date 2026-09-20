#pragma once

// KvmWatchPanel：R-1 内存监视（首次访问归因）页。
//
// 它要回答的问题，是这套 ARK 里其它页都答不了的那一个。快照式检测能告诉用户
// 「SSDT / DriverObject / 回调 / 内核代码现在不对劲」，但答不出**是谁改的、
// 从哪条指令改的、第一次改发生在什么时候**——因为改动那一刻已经过去了。
// 这一页把问题换个方向问：盯住目标，等下一次访问，把那一刻的现场记下来。
//
// 界面上有三件事必须说清楚，因为它们都属于"读起来正确、理解起来会错"的那一类：
//
// - **监视单位是 4 KiB 物理页，不是用户选的那几个字节。** EPT 权限就是页粒度。
//   用户从 DriverObject->MajorFunction[14] 这样一个 8 字节字段建监视，装到硬件
//   上的仍然是那一页。所以请求范围与实际监视页必须并排显示，绝不能把它描述成
//   "8 字节硬件断点"。
// - **请求的访问类型与实际生效的可能不同。** EPT 不允许 W=1 而 R=0，所以"只监视
//   读"在硬件上一定连写也监视了。两栏都留着。
// - **这不是保护。** 命中后原访问照常完成；目标只要把自己那一页换个物理页就不在
//   被监视的页上了；DMA 根本不经过 CPU EPT。它是观察与归因，不是不可绕过的守卫。
//
// 还有一个容易被显示成反面的状态：命中了但事件环没接住。那时"没有事件"与"没被
// 访问过"在事件列表里长得一模一样，而结论正好相反，所以这一页用 watch 自己的
// hitCount / lastHitStatus 来区分，不依赖事件行是否存在。

#include <QHash>
#include <QWidget>

#include <functional>

// 进程归因结构要按值存进成员表，不能只前置声明。
#include "KvmControl.h"

class QLabel;
class QPushButton;
class QTableWidget;
class QTextEdit;

class KvmWatchPanel final : public QWidget
{
public:
    explicit KvmWatchPanel(QWidget* parent = nullptr);

    // onBusyChanged：与其它 KVM 入口共用的串行化回调。
    // 安装与撤销都要独占驱动侧那把状态锁，别处的命令在飞时不能同时下手。
    std::function<void(bool)> onBusyChanged;

    // refreshAsync：后台读一次 watch 表。查询是阻塞 IOCTL，不能在 UI 线程直接调。
    void refreshAsync();

protected:
    void showEvent(QShowEvent* event) override;

private:
    void buildUi();
    void setBusy(bool busy);
    void updateEnabledState();
    // applyWatches：把一次快照铺进表格，并顺带做虚拟地址重映射检测。
    void applyWatches(const QVector<ksword::kvm::KvmWatchEntry>& watches);
    // selectedWatch：当前选中行对应的快照，没选中返回 false。
    bool selectedWatch(ksword::kvm::KvmWatchEntry* entryOut) const;
    void showDetail(const ksword::kvm::KvmWatchEntry& entry);

    void startAdd();
    void startRearm();
    void startRemove();
    void openWriterDisassembly();
    // openTargetMemory：在内存页里打开被监视的那一页。
    void openTargetMemory();
    // openWriterModule：在资源管理器里定位写入者所属的模块文件。
    void openWriterModule();
    // resolveHitProcess：把命中现场的 CR3 归到一个进程上。
    //
    // 单独一个按钮而不是随详情自动跑：它要 attach 遍历全部进程，几百次内核
    // 切换。挂在选中行变化上，光是用方向键扫一遍表格就会把机器压住 —— 而这
    // 一步的结果晚几秒出来不影响任何结论。
    void resolveHitProcess();
    void copyEvidence();
    // exportEvidence：把整张表写成一个文本文件。
    //
    // 与「复制证据」的区别不是范围而是用途：复制是为了贴进一条消息，导出是
    // 为了留档 —— 所以它写的是全部条目，包括尚未命中的那些（"这些目标被盯过
    // 且没被动"同样是结论），以及命中了但事件环没接住的那些。
    void exportEvidence();

    QLabel* m_hintLabel = nullptr;
    QTableWidget* m_table = nullptr;
    QTextEdit* m_detail = nullptr;
    QLabel* m_statusLabel = nullptr;

    QPushButton* m_addButton = nullptr;
    QPushButton* m_rearmButton = nullptr;
    QPushButton* m_removeButton = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_disassembleButton = nullptr;
    QPushButton* m_memoryButton = nullptr;
    QPushButton* m_moduleButton = nullptr;
    QPushButton* m_processButton = nullptr;
    QPushButton* m_copyButton = nullptr;
    QPushButton* m_exportButton = nullptr;

    // 按 CR3 缓存的进程归因。
    //
    // 按 CR3 而不是按 watchId：同一个地址空间被多条监视撞上时答案是同一个，
    // 而重复跑一次几百进程的遍历只是浪费。缓存是快照，所以显示时必须带上
    // "这是后来解析出来的"这层限定，不能说成命中那一刻的事实。
    QHash<quint64, ksword::kvm::KvmProcessAttribution> m_processAttribution;

    bool m_busy = false;
    bool m_queryInFlight = false;
};
