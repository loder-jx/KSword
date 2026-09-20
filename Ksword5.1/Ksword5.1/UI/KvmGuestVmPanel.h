#pragma once

// 「跑第三方虚拟机」页：把"要 VMware / VirtualBox / WSL2 能用，得做哪几件事"
// 写成普通人看得懂的一张清单。
//
// 为什么要单独做一页：这四件事此前散落在三处，而且没有任何地方说它们有先后。
// 三个开关在标题栏的虚拟化菜单里（其中"隐藏身份"那一项连 tooltip 都没有），
// 准备/自检/常驻在「控制」页，重启 vmx86 服务**根本不在界面上**——它写在部署
// 脚本的一行注释里。一个不知道这些的人把开关都点开，VMware 照样打不开，而且
// VMware 给出的理由（"与 Hyper-V 不兼容"）不指向我们。
//
// 这一页只做编排与解释，不新增任何驱动能力：每一步调用的都是既有接口。

#include <QWidget>

#include <functional>

class QLabel;
class QPushButton;

namespace ksword::kvm { struct KvmState; }

class KvmGuestVmPanel final : public QWidget
{
public:
    explicit KvmGuestVmPanel(QWidget* parent = nullptr);

    // 忙时由外层禁用页签切换，与「完整操作」页同一套约定。
    std::function<void(bool)> onBusyChanged;

    void refreshAsync();

protected:
    void showEvent(QShowEvent* event) override;

private:
    // 一步的三块：标题恒定，状态与按钮随每次刷新重算。
    struct StepRow
    {
        QLabel* status = nullptr;
        QPushButton* action = nullptr;
    };

    StepRow addStep(
        class QVBoxLayout* parentLayout,
        int number,
        const QString& title,
        const QString& explanation,
        const QString& actionText,
        const std::function<void()>& onClicked);

    void applyState(const ksword::kvm::KvmState& state);
    void setBusy(bool busy);

    // 在后台线程跑一段阻塞工作，完成后回 UI 线程刷新。
    void runInBackground(const std::function<QString()>& work);

    void enableAllSwitches();
    void startMonitor();
    void restartVmwareDriver();

    // 本页每改动一次配置就调用它，把第 5 步的"已完成"作废。
    // 因为那一步的全部意义就是"在最后一次改动之后重新问过一遍能力"：
    // 改了开关、或重新起了一次 KSwordVM，上一次重启拿到的答案就又旧了。
    void markConfigurationChanged();

    QLabel* m_intro = nullptr;
    QLabel* m_verdict = nullptr;
    QLabel* m_lastMessage = nullptr;
    QPushButton* m_doAll = nullptr;
    QPushButton* m_refresh = nullptr;

    StepRow m_stepAllowNested;
    StepRow m_stepHostGuests;
    StepRow m_stepHideIdentity;
    StepRow m_stepStartMonitor;
    StepRow m_stepRestartVmware;

    bool m_busy = false;
    bool m_queryInFlight = false;

    // m_backendSupported：本页这五步只对 Intel 嵌套 VMX 成立。
    //
    // 三个开关（允许嵌套、允许别人跑在我们下面、隐藏身份）改的都是 VMX 派发
    // 路径上的位，AMD SVM 后端没有对应实现——在 AMD 上按下去不会报错，只会
    // 什么都不发生，而用户会一直以为自己漏了哪一步。所以按后端灰掉并说清楚。
    //
    // 初值取 false：第一次状态查询回来之前后端未知，此时放行按钮等于让用户
    // 在一个还没读出后端的界面上下手。
    bool m_backendSupported = false;

    // 「重启过了吗」只能按本次会话记账：服务当前在跑，不代表它是在三个开关
    // 改完之后才起来的——而那个区别正是这一步存在的理由。宁可说"待重启"，
    // 也不要拿"正在运行"冒充"已经重新问过能力"。
    // 见 markConfigurationChanged()：任何一次改动都会把它清回 false。
    bool m_vmwareDriverRestarted = false;
};
