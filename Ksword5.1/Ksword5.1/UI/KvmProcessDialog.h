#pragma once

// KvmProcessDialog：R-1 进程处置与注入面板。
//
// 这两组能力此前在 GUI 里唯一的入口是「完整命令面板」——那个面板是把主程序
// 当 hvm_ctl 子进程拉起来的探针通路，已经整条摘掉。能力本身没跟着走：处置与
// 注入各有专属 IOCTL，驱动侧是实现完整的生产路径。这一页就是它们的原生入口，
// 与视图 / MSR / CR 三个面板同一个形状。
//
// 两件事放在一页而不是两页，是因为它们共享同一组前置条件，而那组条件是用户
// 最容易撞上的地方：都要 CR3 追踪（靠地址空间认目标）、都要 EPTP 切换后端
// （受限层次和执行视图都靠切指针生效）、安装都要求常驻停着。拆成两页会把同
// 一句话说两遍，而且用户在其中一页上排完障，到另一页还要再排一次。
//
// **这不是安全边界。** 与隐蔽 Hook 同源的性质：失败即放行。目标进程若能让自己
// 的代码页换一个客户物理页（重定位、自改写、换映射），它就不在被拒绝的那一页
// 上了；能改 CR3 的代码也不受约束。它是一条 R0 之外的处置通路，用来在内核 API
// 被挡住时仍然能动手，不是用来对抗一个知道它存在的对手。这句话直接写在界面上，
// 因为把它当边界用是唯一一种"用对了也会出事"的用法。

#include <QDialog>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTabWidget;

class KvmProcessDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmProcessDialog(QWidget* parent = nullptr);

private:
    // buildUi/buildDispositionPage/buildInjectionPage：构造控件树与信号连接。
    void buildUi();
    QWidget* buildDispositionPage();
    QWidget* buildInjectionPage();

    // refreshDispositions/refreshInjections：后台读一次对应的表并刷新。
    void refreshDispositions();
    void refreshInjections();

    // startFreeze/startTerminate/...：发起一次后台写操作。
    // 每一个都先过 confirmDestructiveAction，再过门面里的写权限门。
    void startFreeze();
    void startTerminate();
    void startReleaseDisposition();
    void startReleaseAllDispositions();
    void startInject();
    void startReleaseInjection();
    void startReleaseAllInjections();

    // setBusy：忙碌期间禁用全部动作按钮。两张表共用一个忙碌位，因为驱动侧
    // 那把状态锁本来就是共享的——放两个位只会让界面显示出一个不存在的并发。
    void setBusy(bool busy);
    void updateEnabledState();

    // readSelectedProcessId：取当前页表格选中行的 PID，没选中返回 false。
    bool readSelectedProcessId(QTableWidget* table, unsigned long* processIdOut);

    QTabWidget* m_tabs = nullptr;

    QLineEdit* m_dispositionPidEdit = nullptr;
    QLineEdit* m_dispositionAddressEdit = nullptr;
    QTableWidget* m_dispositionTable = nullptr;
    QPushButton* m_freezeButton = nullptr;
    QPushButton* m_terminateButton = nullptr;
    QPushButton* m_releaseDispositionButton = nullptr;
    QPushButton* m_releaseAllDispositionsButton = nullptr;
    QPushButton* m_refreshDispositionsButton = nullptr;

    QLineEdit* m_injectPidEdit = nullptr;
    QLineEdit* m_injectAddressEdit = nullptr;
    QLineEdit* m_injectLoadLibraryEdit = nullptr;
    QLineEdit* m_injectPathEdit = nullptr;
    QPushButton* m_injectBrowseButton = nullptr;
    QTableWidget* m_injectionTable = nullptr;
    QPushButton* m_injectButton = nullptr;
    QPushButton* m_releaseInjectionButton = nullptr;
    QPushButton* m_releaseAllInjectionsButton = nullptr;
    QPushButton* m_refreshInjectionsButton = nullptr;

    QLabel* m_statusLabel = nullptr;
    bool m_busy = false;
};
