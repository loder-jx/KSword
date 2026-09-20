#include "KvmGuestVmPanel.h"

#include "../Internationalization/LanguageManager.h"
#include "../ksword/service/service.h"
#include "../theme.h"
#include "KvmControl.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QVBoxLayout>

#include <thread>

// 本文件里每一条面向用户的长句都写在**一行**里，不拆成相邻字面量。
// 拆行的话，词条抽取工具会把每个片段都当成一条独立词条收进语言包，而运行时
// `sourceText` 拿到的是拼接后的整串 —— 于是包里多出一堆永远匹配不上的碎片，
// 真正那一条却仍然缺失。仓库里现有的长 tooltip 也都是单行。

namespace
{
    // VMware 的 VMX 驱动服务名。它只在自己启动时问一次 CPU 能力并记住，
    // 所以前面几步改完之后必须让它重新问一遍。
    const wchar_t* const kVmwareDriverService = L"vmx86";

    // Win32 SERVICE_STOPPED / SERVICE_RUNNING，避免为两个常量拉进 winsvc.h。
    constexpr std::uint32_t kServiceStopped = 1U;
    constexpr std::uint32_t kServiceRunning = 4U;

    QString doneMark()
    {
        return ks::i18n::sourceText(QStringLiteral("已完成"));
    }

    QString todoMark()
    {
        return ks::i18n::sourceText(QStringLiteral("还没做"));
    }

    void paintStatus(QLabel* label, const QString& text, bool done)
    {
        if (label == nullptr) { return; }
        label->setText(text);
        label->setStyleSheet(QStringLiteral("color:%1;").arg(
            done ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));
    }
}

KvmGuestVmPanel::KvmGuestVmPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* const outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);

    auto* const scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* const host = new QWidget(scroll);
    auto* const layout = new QVBoxLayout(host);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(10);

    m_intro = new QLabel(host);
    m_intro->setWordWrap(true);
    m_intro->setText(ks::i18n::sourceText(QStringLiteral("本机启用 KSwordVM 之后，它会占住 CPU 的虚拟化功能。VMware、VirtualBox、WSL2、Docker Desktop 要用的是同一套功能，因此必须由 KSwordVM 主动让出来，并且对它们隐藏自己的存在。下面五步全部完成之后，这些软件就能照常打开虚拟机。顺序是有讲究的：前三步是设置，第四步才把 KSwordVM 真正跑起来，第五步让 VMware 重新去问一次 CPU 能力。少做任何一步虚拟机软件都会打不开，而且它给出的错误提示不会提到 KSwordVM。")));
    layout->addWidget(m_intro);

    auto* const buttonRow = new QHBoxLayout();
    m_doAll = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("一键完成全部五步")), host);
    m_doAll->setToolTip(ks::i18n::sourceText(QStringLiteral("按顺序执行：打开三个设置，准备并启动 KSwordVM，最后重启 VMware 的驱动服务。每一步的结果都会显示在下面的清单里。")));
    connect(m_doAll, &QPushButton::clicked, this, [this]() {
        runInBackground([this]() -> QString {
            enableAllSwitches();
            startMonitor();
            restartVmwareDriver();
            return ks::i18n::sourceText(QStringLiteral("五步已执行完，请看下面每一步的状态。"));
        });
    });
    buttonRow->addWidget(m_doAll);

    m_refresh = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新状态")), host);
    connect(m_refresh, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    buttonRow->addWidget(m_refresh);
    buttonRow->addStretch(1);
    layout->addLayout(buttonRow);

    m_stepAllowNested = addStep(layout, 1,
        ks::i18n::sourceText(QStringLiteral("允许 KSwordVM 运行在虚拟机里")),
        ks::i18n::sourceText(QStringLiteral("如果这台电脑本身就是一台虚拟机，或者系统开着「内存完整性」，那么 KSwordVM 只能以这种方式运行。代价是每一条虚拟化指令都要由外面那层软件代为处理，速度会明显变慢。不确定要不要开就开着，它不改动系统任何设置。")),
        ks::i18n::sourceText(QStringLiteral("打开")),
        [this]() {
            runInBackground([this]() -> QString {
                markConfigurationChanged();
                ksword::kvm::setNestedAllowed(true);
                return ks::i18n::sourceText(QStringLiteral("第 1 步已打开。"));
            });
        });

    m_stepHostGuests = addStep(layout, 2,
        ks::i18n::sourceText(QStringLiteral("允许别的虚拟机运行在 KSwordVM 下面")),
        ks::i18n::sourceText(QStringLiteral("这一项和上一项方向相反：上一项是让 KSwordVM 跑在别人下面，这一项是让别人跑在 KSwordVM 下面。不打开的话，VMware 一按「开启此虚拟机」就会失败。它有两个前提：需要先打开「允许 R-1 写操作」，并且关掉「每处理器私有 EPT」，后者和这一项不能同时开，同时开会被整条拒绝。")),
        ks::i18n::sourceText(QStringLiteral("打开")),
        [this]() {
            runInBackground([this]() -> QString {
                if (ksword::kvm::isLocalEptEnabled())
                {
                    return ks::i18n::sourceText(QStringLiteral("打不开：「每处理器私有 EPT」正开着，它和这一项不能同时开，请先关掉它。"));
                }
                if (!ksword::kvm::isWriteAccessEnabled())
                {
                    return ks::i18n::sourceText(QStringLiteral("打不开：需要先打开「允许 R-1 写操作」。"));
                }
                markConfigurationChanged();
                ksword::kvm::setNestedDispatchEnabled(true);
                return ks::i18n::sourceText(QStringLiteral("第 2 步已打开。"));
            });
        });

    m_stepHideIdentity = addStep(layout, 3,
        ks::i18n::sourceText(QStringLiteral("对虚拟机软件隐藏 KSwordVM 的身份")),
        ks::i18n::sourceText(QStringLiteral("这一步不能省。VMware 启动时会先检查 CPU 上有没有别的虚拟化软件，一旦发现就直接弹「与 Hyper-V 不兼容」并退出，它连能力都不会去问，所以前两步做得再对也救不回来。打开之后虚拟机软件就看不到 KSwordVM 了。")),
        ks::i18n::sourceText(QStringLiteral("打开")),
        [this]() {
            runInBackground([this]() -> QString {
                markConfigurationChanged();
                ksword::kvm::setHypervisorHidden(true);
                return ks::i18n::sourceText(QStringLiteral("第 3 步已打开。"));
            });
        });

    m_stepStartMonitor = addStep(layout, 4,
        ks::i18n::sourceText(QStringLiteral("启动 KSwordVM")),
        ks::i18n::sourceText(QStringLiteral("分配资源、做一次自检，然后正式接管 CPU 的虚拟化功能。前三步是设置，只有走完这一步它们才真正生效：设置是在启动的那一刻被读取的，启动之后再改开关不会影响已经跑起来的这一份。")),
        ks::i18n::sourceText(QStringLiteral("启动")),
        [this]() {
            runInBackground([this]() -> QString {
                startMonitor();
                return QString();
            });
        });

    m_stepRestartVmware = addStep(layout, 5,
        ks::i18n::sourceText(QStringLiteral("让 VMware 重新识别 CPU 能力")),
        ks::i18n::sourceText(QStringLiteral("VMware 的驱动只在它自己启动的时候问一次 CPU 支持哪些虚拟化能力，问完就记住了。前面几步改完之后它手里还是旧答案，所以必须让它重启一次重新问。这一步动的是 VMware 自己的服务，不是 KSwordVM；重启前请先关掉所有正在运行的虚拟机。")),
        ks::i18n::sourceText(QStringLiteral("重启 VMware 驱动服务")),
        [this]() {
            runInBackground([this]() -> QString {
                restartVmwareDriver();
                return QString();
            });
        });

    auto* const line = new QFrame(host);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    layout->addWidget(line);

    m_verdict = new QLabel(host);
    m_verdict->setWordWrap(true);
    layout->addWidget(m_verdict);

    m_lastMessage = new QLabel(host);
    m_lastMessage->setWordWrap(true);
    m_lastMessage->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    layout->addWidget(m_lastMessage);

    layout->addStretch(1);
    scroll->setWidget(host);
    outer->addWidget(scroll);
}

KvmGuestVmPanel::StepRow KvmGuestVmPanel::addStep(
    QVBoxLayout* parentLayout,
    const int number,
    const QString& title,
    const QString& explanation,
    const QString& actionText,
    const std::function<void()>& onClicked)
{
    StepRow row;

    auto* const box = new QFrame(parentLayout->parentWidget());
    box->setFrameShape(QFrame::StyledPanel);
    auto* const boxLayout = new QVBoxLayout(box);
    boxLayout->setContentsMargins(12, 10, 12, 10);
    boxLayout->setSpacing(6);

    auto* const headerRow = new QHBoxLayout();
    auto* const titleLabel = new QLabel(
        QStringLiteral("%1. %2").arg(number).arg(title), box);
    titleLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    titleLabel->setWordWrap(true);
    headerRow->addWidget(titleLabel, 1);

    row.status = new QLabel(box);
    headerRow->addWidget(row.status);

    row.action = new QPushButton(actionText, box);
    connect(row.action, &QPushButton::clicked, this, onClicked);
    headerRow->addWidget(row.action);
    boxLayout->addLayout(headerRow);

    auto* const why = new QLabel(explanation, box);
    why->setWordWrap(true);
    why->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    boxLayout->addWidget(why);

    parentLayout->addWidget(box);
    return row;
}

void KvmGuestVmPanel::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    refreshAsync();
}

void KvmGuestVmPanel::setBusy(const bool busy)
{
    m_busy = busy;
    // 「刷新」不看后端：读一次状态在哪台机器上都成立，而它正是用户在 AMD 上
    // 唯一还能按的东西——把它一起灰掉，这一页就没有任何出口了。
    if (m_refresh != nullptr) { m_refresh->setEnabled(!busy); }
    const bool actionsEnabled = !busy && m_backendSupported;
    if (m_doAll != nullptr) { m_doAll->setEnabled(actionsEnabled); }
    for (StepRow* const row : { &m_stepAllowNested, &m_stepHostGuests,
                                &m_stepHideIdentity, &m_stepStartMonitor,
                                &m_stepRestartVmware })
    {
        if (row->action != nullptr) { row->action->setEnabled(actionsEnabled); }
    }
    if (onBusyChanged) { onBusyChanged(busy); }
}

void KvmGuestVmPanel::runInBackground(const std::function<QString()>& work)
{
    if (m_busy) { return; }
    setBusy(true);
    QPointer<KvmGuestVmPanel> safeThis(this);
    std::thread([safeThis, work]() {
        QString message;
        if (work) { message = work(); }
        const ksword::kvm::KvmState state = ksword::kvm::queryState();
        if (safeThis == nullptr) { return; }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, state, message]() {
                if (safeThis == nullptr) { return; }
                safeThis->setBusy(false);
                if (!message.isEmpty() && safeThis->m_lastMessage != nullptr)
                {
                    safeThis->m_lastMessage->setText(message);
                }
                safeThis->applyState(state);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmGuestVmPanel::refreshAsync()
{
    if (m_busy || m_queryInFlight) { return; }
    m_queryInFlight = true;
    QPointer<KvmGuestVmPanel> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmState state = ksword::kvm::queryState();
        if (safeThis == nullptr) { return; }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, state]() {
                if (safeThis == nullptr) { return; }
                safeThis->m_queryInFlight = false;
                safeThis->applyState(state);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmGuestVmPanel::markConfigurationChanged()
{
    m_vmwareDriverRestarted = false;
}

void KvmGuestVmPanel::enableAllSwitches()
{
    markConfigurationChanged();
    ksword::kvm::setNestedAllowed(true);
    if (!ksword::kvm::isLocalEptEnabled() && ksword::kvm::isWriteAccessEnabled())
    {
        ksword::kvm::setNestedDispatchEnabled(true);
    }
    ksword::kvm::setHypervisorHidden(true);
}

void KvmGuestVmPanel::startMonitor()
{
    const ksword::kvm::KvmState before = ksword::kvm::queryState();
    if (before.residentActive) { return; }
    // 重新起一次 KSwordVM，等于让能力过滤器换了一份；vmx86 上一次问到的答案
    // 就此作废，第 5 步必须重做。
    markConfigurationChanged();
    const ksword::kvm::KvmCommandResult prepared = ksword::kvm::ensurePrepared();
    if (!prepared.ok) { return; }
    const ksword::kvm::KvmState prepState = ksword::kvm::queryState();
    (void)ksword::kvm::startResident(prepState.generation);
}

void KvmGuestVmPanel::restartVmwareDriver()
{
    ks::service::ServiceStatus status{};
    if (!ks::service::QueryServiceStatus(kVmwareDriverService, &status))
    {
        // 没装 VMware 就没有这个服务，不是错误。
        return;
    }
    (void)ks::service::StopServiceByName(
        kVmwareDriverService, 15000U, kServiceStopped);
    if (ks::service::StartServiceByName(
            kVmwareDriverService, 15000U, kServiceRunning))
    {
        m_vmwareDriverRestarted = true;
    }
}

void KvmGuestVmPanel::applyState(const ksword::kvm::KvmState& state)
{
    // 后端判据先算：下面五步全都建立在 Intel 的嵌套 VMX 派发上。
    // setBusy 不改忙碌位，只是拿新的 m_backendSupported 把按钮重刷一遍。
    m_backendSupported = state.backend == KSWORD_ARK_HVM_BACKEND_VMX;
    setBusy(m_busy);
    if (!m_backendSupported)
    {
        // 五步全部标成"不适用"而不是"待办"：待办意味着按一下就能推进，
        // 而这里按下去什么都不会发生——那是这一页最容易骗到人的一种显示。
        const QString reason = state.backend == KSWORD_ARK_HVM_BACKEND_SVM
            ? ks::i18n::sourceText(QStringLiteral("这一页只对 Intel 嵌套 VMX 成立。当前是 AMD SVM/NPT 后端：它不提供把第三方虚拟机跑在 KSwordVM 之下的能力，上面五步在这里按下去不会有任何效果。"))
            : ks::i18n::sourceText(QStringLiteral("还读不到虚拟化后端。请先用标题栏的 R0 按钮启动 KswordARK 驱动服务，再回到这一页。"));
        for (StepRow* const row : { &m_stepAllowNested, &m_stepHostGuests,
                                    &m_stepHideIdentity, &m_stepStartMonitor,
                                    &m_stepRestartVmware })
        {
            paintStatus(row->status,
                        ks::i18n::sourceText(QStringLiteral("不适用")), false);
        }
        if (m_verdict != nullptr)
        {
            m_verdict->setText(reason);
            m_verdict->setStyleSheet(QStringLiteral("font-weight:600;"));
        }
        return;
    }
    const bool allowNested = ksword::kvm::isNestedAllowed();
    const bool hostGuests = ksword::kvm::isNestedDispatchEnabled();
    const bool hideIdentity = ksword::kvm::isHypervisorHidden();
    const bool running = state.residentActive;

    paintStatus(m_stepAllowNested.status,
                allowNested ? doneMark() : todoMark(), allowNested);
    paintStatus(m_stepHostGuests.status,
                hostGuests ? doneMark() : todoMark(), hostGuests);
    paintStatus(m_stepHideIdentity.status,
                hideIdentity ? doneMark() : todoMark(), hideIdentity);
    paintStatus(m_stepStartMonitor.status,
                running
                    ? doneMark()
                    : ks::i18n::sourceText(QStringLiteral("没在运行")),
                running);

    ks::service::ServiceStatus vmwareStatus{};
    const bool vmwareInstalled =
        ks::service::QueryServiceStatus(kVmwareDriverService, &vmwareStatus);
    QString vmwareText;
    bool vmwareDone = false;
    if (!vmwareInstalled)
    {
        vmwareText = ks::i18n::sourceText(QStringLiteral("没装 VMware"));
        vmwareDone = true; // 没装就不需要这一步。
    }
    else if (m_vmwareDriverRestarted)
    {
        vmwareText = doneMark();
        vmwareDone = true;
    }
    else
    {
        vmwareText = ks::i18n::sourceText(QStringLiteral("还需重启一次"));
    }
    paintStatus(m_stepRestartVmware.status, vmwareText, vmwareDone);

    // 结论用一句人话，并且只在真正都满足时才说"可以了"。
    QString verdict;
    if (allowNested && hostGuests && hideIdentity && running && vmwareDone)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("现在可以打开 VMware、VirtualBox 或 WSL2 了。如果仍然打不开，请先把已经开着的虚拟机全部关掉，再重启一次 VMware 的驱动服务。"));
    }
    else if (!running)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还不行：KSwordVM 没在运行。请先把上面的设置打开，再执行第 4 步。"));
    }
    else if (!hideIdentity)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还不行：没有隐藏身份，VMware 会直接报「与 Hyper-V 不兼容」并退出。这一项要在启动 KSwordVM 之前设好，改完需要重新启动 KSwordVM 才生效。"));
    }
    else if (!hostGuests)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还不行：没有允许别的虚拟机跑在 KSwordVM 下面，VMware 一开虚拟机就会失败。"));
    }
    else if (!vmwareDone)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("就差最后一步：VMware 的驱动手里还是旧的 CPU 能力答案，重启一次它的服务即可。"));
    }
    else
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还有步骤没完成，请看上面的清单。"));
    }
    if (m_verdict != nullptr)
    {
        m_verdict->setText(verdict);
        m_verdict->setStyleSheet(QStringLiteral("font-weight:600;"));
    }
}
