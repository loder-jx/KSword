#include "KvmWatchPanel.h"

#include "KernelDisassemblyDialog.h"
#include "KvmControl.h"
// 安装表单与四个 ARK 页面共用同一份：两份表单会在"页粒度"和"请求访问与实际
// 访问"这两段说明上慢慢漂开，而那两段恰恰是这功能最容易被误解的地方。
#include "KvmWatchDialog.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QProcess>
#include <QTextStream>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>

#include <thread>

namespace
{
    enum WatchColumn
    {
        WatchColumnId = 0,
        WatchColumnTarget,
        WatchColumnRequestedRange,
        WatchColumnPage,
        WatchColumnRequestedAccess,
        WatchColumnEffectiveAccess,
        WatchColumnMode,
        WatchColumnState,
        WatchColumnHits,
        WatchColumnLastRip,
        WatchColumnModule,
        WatchColumnCount
    };

    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }

    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }


}

KvmWatchPanel::KvmWatchPanel(QWidget* const parent)
    : QWidget(parent)
{
    buildUi();
    updateEnabledState();
}

void KvmWatchPanel::buildUi()
{
    auto* const rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    m_hintLabel = new QLabel(
        text(QStringLiteral("监视一个目标页的下一次访问，命中时记下访问者的现场，然后自动解除并让原访问正常继续 —— 常驻不会因此退出。这是观察与归因，不是保护：命中不阻止访问，监视单位是 4 KiB 页而不是你选的字节数，DMA 改写不经过 CPU 的 EPT，目标把自己那一页换个物理页就不在被监视的页上了。")),
        this);
    m_hintLabel->setWordWrap(true);
    rootLayout->addWidget(m_hintLabel);

    m_table = new QTableWidget(0, WatchColumnCount, this);
    m_table->setObjectName(QStringLiteral("KvmWatchTable"));
    m_table->setHorizontalHeaderLabels(QStringList()
        << text(QStringLiteral("编号"))
        << text(QStringLiteral("目标"))
        << text(QStringLiteral("请求范围"))
        << text(QStringLiteral("监视页"))
        << text(QStringLiteral("请求访问"))
        << text(QStringLiteral("实际访问"))
        << text(QStringLiteral("模式"))
        << text(QStringLiteral("状态"))
        << text(QStringLiteral("命中"))
        << text(QStringLiteral("最近 RIP"))
        << text(QStringLiteral("模块")));
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    rootLayout->addWidget(m_table, 3);

    auto* const buttons = new QGridLayout();
    m_addButton = new QPushButton(
        text(QStringLiteral("添加监视...")), this);
    m_rearmButton = new QPushButton(
        text(QStringLiteral("重新武装")), this);
    m_rearmButton->setToolTip(text(QStringLiteral("保留编号与累计命中次数，让这条监视再等下一次访问。已命中和已失效的都可以重新武装。")));
    m_removeButton = new QPushButton(
        text(QStringLiteral("移除")), this);
    m_refreshButton = new QPushButton(
        text(QStringLiteral("刷新")), this);
    m_disassembleButton = new QPushButton(
        text(QStringLiteral("查看写入者反汇编")), this);
    m_memoryButton = new QPushButton(
        text(QStringLiteral("查看目标内存")), this);
    m_memoryButton->setToolTip(text(QStringLiteral("按被监视的那一页读一段内存。这是**命中之后**的采样，不是命中那一刻的值——EPT violation 发生在写指令退休之前，所以这里读到的可能已经包含那次写入，也可能还包含之后的更多次修改。")));
    m_moduleButton = new QPushButton(
        text(QStringLiteral("查看模块")), this);
    m_moduleButton->setToolTip(text(QStringLiteral("在资源管理器里定位命中 RIP 所属的内核模块文件。RIP 不落在任何已加载模块里时这个按钮不可用。")));
    m_processButton = new QPushButton(
        text(QStringLiteral("解析命中进程")), this);
    m_processButton->setToolTip(text(QStringLiteral("把命中现场记下的 CR3 归到一个进程上。它要逐个进程读回页目录基址，所以是一次显式操作而不是随选中行自动跑。结果是后处理推断：进程可能已经退出、PID 可能已经被回收。")));
    m_copyButton = new QPushButton(
        text(QStringLiteral("复制证据")), this);
    m_exportButton = new QPushButton(
        text(QStringLiteral("导出全部证据...")), this);
    m_exportButton->setToolTip(text(QStringLiteral("把当前监视表里每一条的目标、命中现场与归因写成一个文本文件。已命中但事件环没接住证据的那几条同样会写进去，并标注出来。")));
    buttons->addWidget(m_addButton, 0, 0);
    buttons->addWidget(m_rearmButton, 0, 1);
    buttons->addWidget(m_removeButton, 0, 2);
    buttons->addWidget(m_refreshButton, 0, 3);
    buttons->addWidget(m_disassembleButton, 1, 0);
    buttons->addWidget(m_memoryButton, 1, 1);
    buttons->addWidget(m_moduleButton, 1, 2);
    buttons->addWidget(m_processButton, 1, 3);
    buttons->addWidget(m_copyButton, 0, 4);
    buttons->addWidget(m_exportButton, 1, 4);
    rootLayout->addLayout(buttons);

    m_detail = new QTextEdit(this);
    m_detail->setReadOnly(true);
    m_detail->setLineWrapMode(QTextEdit::NoWrap);
    m_detail->setPlaceholderText(
        text(QStringLiteral("选中一条监视查看它的完整现场与归因。")));
    rootLayout->addWidget(m_detail, 2);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_addButton, &QPushButton::clicked, this, [this]() { startAdd(); });
    connect(m_rearmButton, &QPushButton::clicked, this, [this]() { startRearm(); });
    connect(m_removeButton, &QPushButton::clicked, this, [this]() { startRemove(); });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_disassembleButton, &QPushButton::clicked, this, [this]() {
        openWriterDisassembly();
    });
    connect(m_memoryButton, &QPushButton::clicked, this, [this]() {
        openTargetMemory();
    });
    connect(m_moduleButton, &QPushButton::clicked, this, [this]() {
        openWriterModule();
    });
    connect(m_processButton, &QPushButton::clicked, this, [this]() {
        resolveHitProcess();
    });
    connect(m_copyButton, &QPushButton::clicked, this, [this]() { copyEvidence(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportEvidence(); });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
        ksword::kvm::KvmWatchEntry entry;
        if (selectedWatch(&entry))
        {
            showDetail(entry);
        }
        updateEnabledState();
    });
}

void KvmWatchPanel::showEvent(QShowEvent* const event)
{
    QWidget::showEvent(event);
    refreshAsync();
}

void KvmWatchPanel::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
    if (onBusyChanged)
    {
        onBusyChanged(busy);
    }
}

void KvmWatchPanel::updateEnabledState()
{
    const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : text(QStringLiteral("R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能安装或撤销监视"));
    ksword::kvm::KvmWatchEntry entry;
    const bool hasSelection = selectedWatch(&entry);

    if (m_addButton != nullptr)
    {
        m_addButton->setEnabled(writeAllowed && !m_busy);
        m_addButton->setToolTip(writeHint);
    }
    if (m_rearmButton != nullptr)
    {
        m_rearmButton->setEnabled(writeAllowed && !m_busy && hasSelection);
        m_rearmButton->setToolTip(writeHint);
    }
    if (m_removeButton != nullptr)
    {
        m_removeButton->setEnabled(writeAllowed && !m_busy && hasSelection);
        m_removeButton->setToolTip(writeHint);
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(!m_busy);
    }
    // 反汇编与复制证据只在真的有一次命中之后才有东西可看。
    const bool hasHit = hasSelection && entry.hitCount != 0UL;
    if (m_disassembleButton != nullptr)
    {
        m_disassembleButton->setEnabled(!m_busy && hasHit && entry.lastHitRip != 0ULL);
    }
    if (m_memoryButton != nullptr)
    {
        // 目标内存不要求命中：还没命中的目标同样值得看一眼当前内容。
        m_memoryButton->setEnabled(!m_busy && hasSelection &&
            entry.physicalPage != 0ULL);
    }
    if (m_moduleButton != nullptr)
    {
        // 归不到模块时按钮就该是灰的，而不是点了弹一个"未知"。
        m_moduleButton->setEnabled(!m_busy && hasHit &&
            entry.lastHitRip != 0ULL &&
            ksword::kvm::attributeKernelAddress(entry.lastHitRip).resolved);
    }
    if (m_processButton != nullptr)
    {
        m_processButton->setEnabled(!m_busy && hasHit && entry.lastHitCr3 != 0ULL);
    }
    if (m_copyButton != nullptr)
    {
        m_copyButton->setEnabled(hasSelection);
    }
    if (m_exportButton != nullptr)
    {
        // 导出不需要选中任何一条：它写的是整张表。
        m_exportButton->setEnabled(m_table != nullptr && m_table->rowCount() > 0);
    }
}

bool KvmWatchPanel::selectedWatch(
    ksword::kvm::KvmWatchEntry* const entryOut) const
{
    if (m_table == nullptr)
    {
        return false;
    }
    const int row = m_table->currentRow();
    if (row < 0 || m_table->item(row, WatchColumnId) == nullptr)
    {
        return false;
    }
    const QVariant stored =
        m_table->item(row, WatchColumnId)->data(Qt::UserRole);
    if (!stored.isValid())
    {
        return false;
    }
    // 整条快照存在行上而不是逐列反解析：表格里的每一列都是给人读的文字，
    // 从文字反推回数值会在第一个本地化的词上出错。
    *entryOut = stored.value<ksword::kvm::KvmWatchEntry>();
    return true;
}

void KvmWatchPanel::refreshAsync()
{
    if (m_queryInFlight || m_busy)
    {
        return;
    }
    m_queryInFlight = true;
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmWatchResult result = ksword::kvm::listWatches();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_queryInFlight = false;
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(result.message);
                    return;
                }
                safeThis->applyWatches(result.watches);
                safeThis->m_statusLabel->setText(
                    text(QStringLiteral("当前有 %1 条内存监视。"))
                        .arg(result.watchCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::applyWatches(
    const QVector<ksword::kvm::KvmWatchEntry>& watches)
{
    m_table->setRowCount(watches.size());
    for (int row = 0; row < watches.size(); ++row)
    {
        const ksword::kvm::KvmWatchEntry& entry = watches.at(row);
        const auto setCell = [this, row](const int column, const QString& value) {
            auto* const item = new QTableWidgetItem(value);
            item->setToolTip(value);
            m_table->setItem(row, column, item);
            return item;
        };
        auto* const idItem = setCell(
            WatchColumnId, QString::number(entry.watchId));
        idItem->setData(Qt::UserRole, QVariant::fromValue(entry));
        setCell(WatchColumnTarget,
            entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                ? text(QStringLiteral("虚拟 %1")).arg(hex64(entry.requestedAddress))
                : text(QStringLiteral("物理 %1")).arg(hex64(entry.requestedAddress)));
        setCell(WatchColumnRequestedRange,
            text(QStringLiteral("%1 字节")).arg(entry.requestedLength));
        // 监视页那一栏把 4096 明写出来：两栏并排才说得清粒度差别。
        setCell(WatchColumnPage,
            text(QStringLiteral("%1（4096 字节）")).arg(hex64(entry.physicalPage)));
        setCell(WatchColumnRequestedAccess,
            ksword::kvm::describeWatchAccess(entry.requestedAccess));
        setCell(WatchColumnEffectiveAccess,
            ksword::kvm::describeWatchAccess(entry.effectiveAccess));
        setCell(WatchColumnMode, text(QStringLiteral("首次访问")));
        setCell(WatchColumnState,
            ksword::kvm::describeWatchState(entry.state));
        // 命中列同时承载"证据在不在"：命中过但事件丢了，与从未命中，
        // 在事件列表里长得一样而结论相反。
        setCell(WatchColumnHits,
            entry.lastHitStatus == KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST
                ? text(QStringLiteral("%1（事件已丢失）")).arg(entry.hitCount)
                : QString::number(entry.hitCount));
        setCell(WatchColumnLastRip,
            entry.lastHitRip != 0ULL ? hex64(entry.lastHitRip) : QStringLiteral("-"));
        QString moduleText = QStringLiteral("-");
        if (entry.lastHitRip != 0ULL)
        {
            const ksword::kvm::KvmWatchAttribution attribution =
                ksword::kvm::attributeKernelAddress(entry.lastHitRip);
            // 有导出符号就用 `module!Symbol+0x..`，没有才退回 `module.sys+0xRVA`。
            // 两种都是真话，区别只是精度；编一个最近的名字出来才是错的。
            moduleText = !attribution.resolved
                ? text(QStringLiteral("未知可执行区域"))
                : attribution.symbolName.isEmpty()
                    ? QStringLiteral("%1+0x%2")
                        .arg(attribution.moduleName)
                        .arg(attribution.relativeAddress, 0, 16)
                    : QStringLiteral("%1!%2+0x%3")
                        .arg(attribution.moduleName)
                        .arg(attribution.symbolName)
                        .arg(attribution.symbolOffset, 0, 16);
        }
        setCell(WatchColumnModule, moduleText);
    }
    m_table->resizeColumnsToContents();
    updateEnabledState();
}

void KvmWatchPanel::showDetail(const ksword::kvm::KvmWatchEntry& entry)
{
    QStringList lines;
    lines << text(QStringLiteral("目标"));
    lines << text(QStringLiteral("  请求地址        %1"))
        .arg(hex64(entry.requestedAddress));
    lines << text(QStringLiteral("  请求长度        %1 字节"))
        .arg(entry.requestedLength);
    lines << text(QStringLiteral("  实际监视页      %1，4096 字节"))
        .arg(hex64(entry.physicalPage));
    lines << text(QStringLiteral("  请求访问        %1"))
        .arg(ksword::kvm::describeWatchAccess(entry.requestedAccess));
    lines << text(QStringLiteral("  实际访问        %1"))
        .arg(ksword::kvm::describeWatchAccess(entry.effectiveAccess));
    lines << text(QStringLiteral("  模式            首次访问"));
    lines << QString();

    // 虚拟地址重映射检测。
    //
    // 这条监视绑死在武装那一刻解析出来的物理页上，不会跟着 VA 的新映射走。
    // 检测不出来时**不能**继续显示成"正在监视该虚拟地址"——那是一句读起来
    // 正确、实际可能完全不成立的话。
    if (entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL &&
        entry.requestedAddress != 0ULL)
    {
        const ksword::kvm::KvmMemoryResult current =
            ksword::kvm::translate(0, entry.requestedAddress);
        if (current.ok && current.physicalAddress != 0ULL)
        {
            const unsigned long long currentPage =
                current.physicalAddress & ~0xFFFULL;
            lines << (currentPage == entry.physicalPage
                ? text(QStringLiteral("映射核对        当前虚拟地址仍然落在被监视的那一页上。"))
                : text(QStringLiteral("映射核对        **当前虚拟地址已经指向 %1，与武装时的 %2 不是同一页。这条监视仍然盯着武装时那一页，不再对应该虚拟地址。**"))
                    .arg(hex64(currentPage))
                    .arg(hex64(entry.physicalPage)));
        }
        else
        {
            lines << text(QStringLiteral("映射核对        当前翻译不出物理页，无法核对该虚拟地址是否还指向被监视的那一页。"));
        }
        lines << QString();
    }

    lines << text(QStringLiteral("命中"));
    if (entry.hitCount == 0UL)
    {
        lines << text(QStringLiteral("  尚未命中。"));
    }
    else
    {
        lines << text(QStringLiteral("  累计命中        %1 次"))
            .arg(entry.hitCount);
        lines << text(QStringLiteral("  事件序号        %1"))
            .arg(entry.lastHitSequence);
        lines << text(QStringLiteral("  证据状态        %1"))
            .arg(entry.lastHitStatus ==
                    KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED
                ? text(QStringLiteral("事件已发布"))
                : text(QStringLiteral("已命中，但事件环没接住这条证据")));
        lines << text(QStringLiteral("  处理器          %1:%2"))
            .arg(entry.lastHitProcessorGroup)
            .arg(entry.lastHitProcessorNumber);
        lines << text(QStringLiteral("  客户物理地址    %1"))
            .arg(hex64(entry.lastHitGuestPhysicalAddress));
        lines << text(QStringLiteral("  客户线性地址    %1"))
            .arg(entry.lastHitGuestLinearValid
                ? hex64(entry.lastHitGuestLinearAddress)
                : text(QStringLiteral("处理器未报告")));
        // 范围命中只在 CPU 给了有效线性地址时才有意义；给不出时说"无法判断"，
        // 而不是默认成"不在范围内"。
        lines << text(QStringLiteral("  落在请求范围内  %1"))
            .arg(!entry.lastHitGuestLinearValid
                ? text(QStringLiteral("无法判断（没有有效的客户线性地址）"))
                : entry.lastHitRangeMatch
                    ? text(QStringLiteral("是"))
                    : text(QStringLiteral("否，落在同一页的其它偏移上")));
        lines << text(QStringLiteral("  RIP             %1"))
            .arg(hex64(entry.lastHitRip));
        lines << text(QStringLiteral("  RSP             %1"))
            .arg(hex64(entry.lastHitRsp));
        lines << text(QStringLiteral("  CR3             %1"))
            .arg(entry.lastHitCr3 != 0ULL
                ? hex64(entry.lastHitCr3)
                : text(QStringLiteral("未采集")));
        lines << QString();
        lines << text(QStringLiteral("归因"));
        const ksword::kvm::KvmWatchAttribution attribution =
            ksword::kvm::attributeKernelAddress(entry.lastHitRip);
        if (attribution.resolved)
        {
            lines << text(QStringLiteral("  模块            %1"))
                .arg(attribution.moduleName);
            lines << text(QStringLiteral("  模块路径        %1"))
                .arg(attribution.modulePath);
            lines << text(QStringLiteral("  模块内偏移      +0x%1"))
                .arg(attribution.relativeAddress, 0, 16);
            // 符号只来自导出表：它答不出静态函数，所以"没有符号"不等于"这个
            // 地址不在函数里"，只等于"它前面没有导出符号"。这句差别要说出来，
            // 否则空符号会被当成异常信号。
            lines << (attribution.symbolName.isEmpty()
                ? text(QStringLiteral("  符号            该地址之前没有导出符号（只解析导出表，不解析 PDB；静态函数本就不在其中）。"))
                : text(QStringLiteral("  符号            %1!%2+0x%3"))
                    .arg(attribution.moduleName)
                    .arg(attribution.symbolName)
                    .arg(attribution.symbolOffset, 0, 16));
        }
        else
        {
            // 归不到模块是一条结论而不是失败：它本身就是可疑的读数。
            lines << text(QStringLiteral("  模块            未知可执行区域 —— 这个 RIP 不落在任何已加载内核模块的映像范围内。"));
            lines << text(QStringLiteral("                  用“查看写入者反汇编”直接看那一段代码。"));
        }
        /*
         * 进程归因是后处理，而且是显式的一步。
         *
         * 没解析过时显示"还没解析"，不显示"未知"——后者把"没问"和"问过了没有"
         * 说成同一件事，而这两句话里只有后一句是结论。
         */
        if (entry.lastHitCr3 == 0ULL)
        {
            lines << text(QStringLiteral("  进程            命中现场没有记下地址空间，无从归因。"));
        }
        else
        {
            const auto cached = m_processAttribution.constFind(entry.lastHitCr3);
            lines << (cached != m_processAttribution.constEnd()
                ? text(QStringLiteral("  进程            %1"))
                    .arg(ksword::kvm::describeProcessAttribution(*cached))
                : text(QStringLiteral("  进程            尚未解析。点“解析命中进程”按 CR3 反查——这一步要逐个进程读页目录基址，所以不随选中行自动跑。")));
        }
    }
    lines << QString();
    lines << text(QStringLiteral("HVM"));
    lines << text(QStringLiteral("  监视状态        %1"))
        .arg(ksword::kvm::describeWatchState(entry.state));
    lines << text(QStringLiteral("  武装代次        %1"))
        .arg(entry.armedGeneration);
    m_detail->setPlainText(lines.join(QLatin1Char('\n')));
}

void KvmWatchPanel::startAdd()
{
    KvmWatchAddDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    if (!dialog.addressValid())
    {
        m_statusLabel->setText(
            text(QStringLiteral("地址不是合法的非零十六进制数。")));
        return;
    }
    const ksword::kvm::KvmWatchTarget target = dialog.target();
    if (target.access == 0UL)
    {
        m_statusLabel->setText(
            text(QStringLiteral("请至少选择一种要监视的访问类型。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在安装监视...")));
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, target]() {
        const ksword::kvm::KvmWatchResult result =
            ksword::kvm::addWatch(target);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::startRearm()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        m_statusLabel->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在重新武装...")));
    const unsigned long watchId = entry.watchId;
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, watchId]() {
        const ksword::kvm::KvmWatchResult result =
            ksword::kvm::rearmWatch(watchId);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::startRemove()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        m_statusLabel->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral("正在移除监视...")));
    const unsigned long watchId = entry.watchId;
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, watchId]() {
        const ksword::kvm::KvmWatchResult result =
            ksword::kvm::removeWatch(watchId);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::openWriterDisassembly()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) ||
        entry.lastHitRip == 0ULL)
    {
        return;
    }
    /*
     * 从命中的 RIP 往前退一点再开始反汇编。
     *
     * RIP 指向的是**尚未完成**的那条指令：EPT violation 发生在导致访问的指令
     * 退休之前。只从 RIP 开始看，用户看到的是那条指令本身，看不到它前面几条
     * 在算什么地址——而"这个写是怎么被算出来的"往往才是要找的东西。
     */
    const unsigned long long start = entry.lastHitRip >= 0x40ULL
        ? entry.lastHitRip - 0x40ULL
        : entry.lastHitRip;
    ks::ui::KernelDisassemblyDialog::openKernelAddress(
        this,
        start,
        text(QStringLiteral("内存监视 #%1 命中的 RIP %2"))
            .arg(entry.watchId)
            .arg(hex64(entry.lastHitRip)),
        0x200U);
}

void KvmWatchPanel::openTargetMemory()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.physicalPage == 0ULL)
    {
        return;
    }
    /*
     * 优先按虚拟地址读，读不到再退回物理页。
     *
     * 两者不等价：虚拟地址读的是"这个 VA 现在指向的东西"，物理页读的是"被监视
     * 的那一页"。重映射之后这两个是不同的页，而用户要看的几乎总是后者 —— 所以
     * 物理页读法是退路，不是降级，读数里要说清楚读的是哪一个。
     */
    const bool byVirtual =
        entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL &&
        entry.requestedAddress != 0ULL;
    const unsigned long long address = byVirtual
        ? entry.requestedAddress
        : entry.physicalPage;
    const ksword::kvm::KvmMemoryResult result = byVirtual
        ? ksword::kvm::readVirtual(0, address, 256U)
        : ksword::kvm::readPhysical(address, 256U);
    if (!result.ok)
    {
        m_statusLabel->setText(
            text(QStringLiteral("读不到目标内存：%1")).arg(result.message));
        return;
    }
    QStringList lines;
    lines << text(QStringLiteral("目标内存（命中之后的采样，不是命中那一刻的值）"));
    lines << (byVirtual
        ? text(QStringLiteral("  按虚拟地址 %1 读 %2 字节"))
            .arg(hex64(address)).arg(result.data.size())
        : text(QStringLiteral("  按被监视的物理页 %1 读 %2 字节"))
            .arg(hex64(address)).arg(result.data.size()));
    lines << QString();
    for (int offset = 0; offset < result.data.size(); offset += 16)
    {
        const QByteArray chunk = result.data.mid(offset, 16);
        lines << QStringLiteral("  %1  %2")
            .arg(hex64(address + static_cast<unsigned long long>(offset)))
            .arg(QString::fromLatin1(chunk.toHex(' ')));
    }
    m_detail->setPlainText(lines.join(QLatin1Char('\n')));
    m_statusLabel->setText(text(QStringLiteral(
        "已读出目标内存。这是命中之后的采样：EPT violation 发生在写指令退休之前，所以这里看到的可能已经包含那次写入，也可能还包含之后的更多次修改。")));
}

void KvmWatchPanel::openWriterModule()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitRip == 0ULL)
    {
        return;
    }
    const ksword::kvm::KvmWatchAttribution attribution =
        ksword::kvm::attributeKernelAddress(entry.lastHitRip);
    if (!attribution.resolved || attribution.modulePath.isEmpty())
    {
        m_statusLabel->setText(text(QStringLiteral(
            "这个 RIP 不落在任何已加载内核模块里，没有模块文件可打开。")));
        return;
    }
    /*
     * 内核回报的是 \SystemRoot\ 这类 NT 路径，资源管理器不认。
     *
     * 转换失败时不要退回"就用原串试试"：资源管理器会拿一个不存在的路径开一个
     * 默认目录，看起来像成功了，而用户会以为自己正在看那个模块所在的目录。
     */
    const QString win32Path = ksword::kvm::toWin32ModulePath(attribution.modulePath);
    if (win32Path.isEmpty() || !QFileInfo::exists(win32Path))
    {
        m_statusLabel->setText(
            text(QStringLiteral("模块文件 %1 在磁盘上找不到。"))
                .arg(attribution.modulePath));
        return;
    }
    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        QStringList() << QStringLiteral("/select,")
                      << QDir::toNativeSeparators(win32Path));
    m_statusLabel->setText(
        text(QStringLiteral("已在资源管理器里定位 %1。")).arg(win32Path));
}

void KvmWatchPanel::resolveHitProcess()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitCr3 == 0ULL)
    {
        return;
    }
    const quint64 cr3 = entry.lastHitCr3;
    setBusy(true);
    m_statusLabel->setText(text(QStringLiteral(
        "正在按 CR3 逐个进程反查地址空间...")));
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, cr3]() {
        const ksword::kvm::KvmProcessAttribution attribution =
            ksword::kvm::attributeProcessByCr3(cr3);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, cr3, attribution]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_processAttribution.insert(cr3, attribution);
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(
                    ksword::kvm::describeProcessAttribution(attribution));
                ksword::kvm::KvmWatchEntry selected;
                if (safeThis->selectedWatch(&selected))
                {
                    safeThis->showDetail(selected);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::exportEvidence()
{
    if (m_table == nullptr || m_table->rowCount() == 0)
    {
        return;
    }
    const QString path = QFileDialog::getSaveFileName(
        this,
        text(QStringLiteral("导出内存监视证据")),
        QStringLiteral("hvm-memory-watch-%1.txt")
            .arg(QDateTime::currentDateTime().toString(
                QStringLiteral("yyyyMMdd-HHmmss"))),
        text(QStringLiteral("文本文件 (*.txt)")));
    if (path.isEmpty())
    {
        return;
    }
    QStringList blocks;
    blocks << text(QStringLiteral("KSword R-1 内存监视证据"));
    blocks << text(QStringLiteral("导出时间：%1"))
        .arg(QDateTime::currentDateTime().toString(Qt::ISODate));
    // 边界写在最前面：这份文件会被单独传阅，而"这不是保护"那句话不能留在
    // 界面上没跟出来。
    blocks << text(QStringLiteral("这是观察与归因记录，不是保护：命中不阻止访问；硬件监视单位是 4 KiB 页而不是请求范围；DMA 改写不经过 CPU 的 EPT；虚拟地址的绑定在武装那一刻定死，之后的重映射不跟踪。"));
    blocks << QString();
    for (int row = 0; row < m_table->rowCount(); ++row)
    {
        QTableWidgetItem* const item = m_table->item(row, WatchColumnId);
        if (item == nullptr)
        {
            continue;
        }
        const QVariant stored = item->data(Qt::UserRole);
        if (!stored.isValid())
        {
            continue;
        }
        // 复用详情框那一份格式：屏幕上看到的和导出的必须是同一份东西，
        // 另拼一份会让两者随时间漂开。
        showDetail(stored.value<ksword::kvm::KvmWatchEntry>());
        blocks << QStringLiteral("================================");
        blocks << m_detail->toPlainText();
        blocks << QString();
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        m_statusLabel->setText(
            text(QStringLiteral("导出失败：无法写入 %1。")).arg(path));
        return;
    }
    // 显式 UTF-8：这份文件里全是中文标签，跟着系统区域走会在别人机器上变成乱码。
    QTextStream stream(&file);
    stream.setEncoding(QStringConverter::Utf8);
    stream << blocks.join(QLatin1Char('\n'));
    file.close();
    m_statusLabel->setText(
        text(QStringLiteral("已导出 %1 条监视的完整证据到 %2。"))
            .arg(m_table->rowCount())
            .arg(path));
    // 导出会把详情框停在最后一条上；把选中那一条重新画回去，免得屏幕上
    // 显示的与选中行对不上。
    ksword::kvm::KvmWatchEntry selected;
    if (selectedWatch(&selected))
    {
        showDetail(selected);
    }
}

void KvmWatchPanel::copyEvidence()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        return;
    }
    // 直接复制详情框的原文：屏幕上看到的和粘贴出去的必须是同一份东西，
    // 另拼一份格式会让两者随时间漂开。
    showDetail(entry);
    QApplication::clipboard()->setText(m_detail->toPlainText());
    m_statusLabel->setText(
        text(QStringLiteral("已把这条监视的完整证据复制到剪贴板。")));
}
