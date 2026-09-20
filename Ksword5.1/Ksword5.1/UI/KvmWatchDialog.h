#pragma once

// KvmWatchDialog：内存监视的安装对话框，以及给其它页面用的统一入口。
//
// 存在的理由是 issue #195 第十四节那句话：功能不能永远只停留在 HVM 实验页。
// SSDT 页、DriverObject 页、内存页、反汇编页的作者不应该、也没理由去理解
// GPA、EPT 叶、ruleId 这些东西——他们手里有的是"一个地址和一句人话描述"，
// 而那正好就是 openHvmWatch 要的全部输入。
//
// 这一层替调用方承担三件他们不该关心的事：
// - 地址翻译与页对齐（EPT 是页粒度，用户选的 8 字节要与整页并排显示）；
// - 前置条件（写权限门、常驻必须停着、目标页不能已被别的 EPT 机制占着）；
// - 结果解释（冲突时指名占用者，而不是丢一个协议状态码）。

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;

namespace ksword::kvm
{
    struct KvmWatchTarget;
}

namespace ks::ui
{
    // HvmWatchRequest：一次来自其它页面的监视请求。
    struct HvmWatchRequest
    {
        // 地址是内核虚拟地址（真）还是物理地址（假）。
        bool virtualAddress = true;
        quint64 address = 0;
        // 调用方真正关心的字节数。0 表示整页。
        //
        // 它不改变硬件监视的范围，只决定命中后能不能判断这次访问落在调用方
        // 关心的那几个字节上。SSDT 一项是 4 或 8 字节，MajorFunction 一项是
        // 8 字节——填准了，"同一页的其它偏移"与"你的目标"才分得开。
        quint64 length = 0;
        // KSWORD_ARK_HVM_EPT_ACCESS_* 的组合，作为对话框里的初始勾选。
        unsigned long access = 0;
        // 目标的人话描述，直接显示给用户，例如
        // "\Driver\Foo MajorFunction[IRP_MJ_DEVICE_CONTROL]"。
        QString label;
    };

    // openHvmWatch：打开安装对话框并预填目标；用户确认后安装。
    //
    // 非阻塞语义上与其它 KVM 面板一致：对话框是模态的（用户正在对一个具体
    // 目标下手，此刻不该同时去点别处），安装本身放到后台线程，因为它是阻塞
    // IOCTL。安装结果以一次消息框回报。
    void openHvmWatch(QWidget* parent, const HvmWatchRequest& request);
}

// KvmWatchAddDialog：安装表单。
//
// 内存监视页与上面那个统一入口共用同一份表单，而不是各写一个：两份表单会在
// "页粒度"和"请求访问与实际访问"这两段说明上慢慢漂开，而那两段恰恰是这个
// 功能最容易被误解的地方。
class KvmWatchAddDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmWatchAddDialog(QWidget* parent = nullptr);

    // prefill：由统一入口预填目标。label 非空时在顶部显示"正在监视：<label>"，
    // 并把地址栏设为只读——调用方已经算好了地址，让用户在这里改它只会让
    // 屏幕上的描述与实际监视的东西对不上。
    void prefill(const ks::ui::HvmWatchRequest& request);

    ksword::kvm::KvmWatchTarget target() const;
    bool addressValid() const;

private:
    void updateGranularity();

    QLabel* m_targetLabel = nullptr;
    QComboBox* m_addressKind = nullptr;
    QLineEdit* m_address = nullptr;
    QLineEdit* m_length = nullptr;
    QCheckBox* m_read = nullptr;
    QCheckBox* m_write = nullptr;
    QCheckBox* m_execute = nullptr;
    QLabel* m_granularity = nullptr;
};
