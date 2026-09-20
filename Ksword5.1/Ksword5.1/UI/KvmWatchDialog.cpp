#include "KvmWatchDialog.h"

#include "KvmControl.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>

#include <thread>

namespace
{
    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }

    /* 解析可带 0x 前缀的十六进制。 */
    bool parseHex(const QString& input, unsigned long long* valueOut)
    {
        QString compact = input.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        // 允许分隔用的反引号：调试器和本程序自己都用它显示 64 位地址，
        // 用户从别处复制过来的地址十有八九带着它。
        compact.remove(QLatin1Char('`'));
        if (compact.isEmpty())
        {
            return false;
        }
        bool converted = false;
        const unsigned long long value = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = value;
        return true;
    }
}

KvmWatchAddDialog::KvmWatchAddDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(text(QStringLiteral("添加内存监视")));
    setObjectName(QStringLiteral("KvmWatchAddDialog"));
    auto* const rootLayout = new QVBoxLayout(this);

    m_targetLabel = new QLabel(this);
    m_targetLabel->setWordWrap(true);
    m_targetLabel->setVisible(false);
    m_targetLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(m_targetLabel);

    auto* const form = new QFormLayout();
    m_addressKind = new QComboBox(this);
    m_addressKind->addItem(text(QStringLiteral("内核虚拟地址")), true);
    m_addressKind->addItem(text(QStringLiteral("物理地址")), false);
    form->addRow(text(QStringLiteral("地址类型")), m_addressKind);

    m_address = new QLineEdit(this);
    m_address->setPlaceholderText(QStringLiteral("FFFFF80112345678"));
    form->addRow(text(QStringLiteral("地址（十六进制）")), m_address);

    m_length = new QLineEdit(this);
    m_length->setPlaceholderText(QStringLiteral("8"));
    m_length->setToolTip(text(QStringLiteral("你真正关心的字节数。它不改变硬件监视的范围（那永远是整页），只决定命中后能不能判断这次访问落在你关心的那几个字节上。留空表示整页。")));
    form->addRow(text(QStringLiteral("关心的长度（十进制字节）")), m_length);
    rootLayout->addLayout(form);

    auto* const accessRow = new QGridLayout();
    m_read = new QCheckBox(text(QStringLiteral("读")), this);
    m_write = new QCheckBox(text(QStringLiteral("写")), this);
    m_execute = new QCheckBox(text(QStringLiteral("执行")), this);
    m_write->setChecked(true);
    accessRow->addWidget(
        new QLabel(text(QStringLiteral("监视的访问类型")), this), 0, 0);
    accessRow->addWidget(m_read, 0, 1);
    accessRow->addWidget(m_write, 0, 2);
    accessRow->addWidget(m_execute, 0, 3);
    rootLayout->addLayout(accessRow);

    rootLayout->addWidget(new QLabel(
        text(QStringLiteral("模式：首次访问（当前唯一支持）")), this));

    m_granularity = new QLabel(this);
    m_granularity->setWordWrap(true);
    m_granularity->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_granularity);

    auto* const buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(text(QStringLiteral("武装")));
    rootLayout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_length, &QLineEdit::textChanged, this, [this](const QString&) {
        updateGranularity();
    });
    connect(m_read, &QCheckBox::toggled, this, [this](bool) {
        updateGranularity();
    });
    updateGranularity();
    resize(560, 360);
}

void KvmWatchAddDialog::prefill(const ks::ui::HvmWatchRequest& request)
{
    m_addressKind->setCurrentIndex(request.virtualAddress ? 0 : 1);
    m_address->setText(QStringLiteral("%1")
        .arg(request.address, 16, 16, QLatin1Char('0')).toUpper());
    if (request.length != 0)
    {
        m_length->setText(QString::number(request.length));
    }
    m_read->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL);
    m_write->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL);
    m_execute->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL);
    if (!request.label.isEmpty())
    {
        m_targetLabel->setText(
            text(QStringLiteral("正在监视：%1")).arg(request.label));
        m_targetLabel->setVisible(true);
        /*
         * 地址栏只读。
         *
         * 调用方已经把"这一项在哪儿"算好了，而顶上那行描述说的正是那个目标。
         * 放开让用户在这里改地址，屏幕上的描述就会与实际监视的东西对不上 ——
         * 之后每一条证据都挂在一句错误的标题下面。要监视别的地址，从内存监视
         * 页手工添加。
         */
        m_address->setReadOnly(true);
        m_addressKind->setEnabled(false);
    }
    updateGranularity();
}

void KvmWatchAddDialog::updateGranularity()
{
    bool converted = false;
    const unsigned long long length =
        m_length->text().trimmed().toULongLong(&converted, 10);
    const unsigned long long requested =
        converted && length != 0ULL ? length : 4096ULL;
    QString note = text(QStringLiteral("EPT 的监视单位是页：你请求 %1 字节，实际装到硬件上的是它所在的整个 4096 字节页。命中后如果 CPU 报告了有效的客户线性地址，界面会另外告诉你这次访问是否落在你请求的那一段里。"))
        .arg(requested);
    if (m_read->isChecked())
    {
        // 这句必须在勾"读"的时候就出现，而不是等安装完才在表里被发现：
        // 用户是在这一刻决定要不要接受"连写也会被监视"的。
        note += QLatin1Char('\n');
        note += text(QStringLiteral("已勾选“读”：EPT 不允许可写而不可读，所以实际生效的监视一定同时包含写；处理器不支持仅执行叶项时还会连带包含执行。表格里的“实际访问”一栏显示归一化后的结果。"));
    }
    m_granularity->setText(note);
}

ksword::kvm::KvmWatchTarget KvmWatchAddDialog::target() const
{
    ksword::kvm::KvmWatchTarget result;
    result.virtualAddress = m_addressKind->currentData().toBool();
    unsigned long long address = 0;
    if (parseHex(m_address->text(), &address))
    {
        result.address = address;
    }
    bool converted = false;
    const unsigned long long length =
        m_length->text().trimmed().toULongLong(&converted, 10);
    result.length = converted ? length : 0ULL;
    result.access =
        (m_read->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_READ : 0UL) |
        (m_write->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_WRITE : 0UL) |
        (m_execute->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE : 0UL);
    return result;
}

bool KvmWatchAddDialog::addressValid() const
{
    unsigned long long address = 0;
    return parseHex(m_address->text(), &address) && address != 0;
}

namespace ks::ui
{
    void openHvmWatch(QWidget* const parent, const HvmWatchRequest& request)
    {
        /*
         * 写权限门在最前面。
         *
         * 它是进程内的开关，不需要发任何 IOCTL 就能判，而且是最常见的拒绝
         * 原因。先问它，用户就不用先填完一张表单再被拒。
         */
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("R-1 写权限未开启：请先在标题栏 KVM 按钮的右键菜单里打开它，再安装内存监视。")));
            return;
        }
        KvmWatchAddDialog dialog(parent);
        dialog.prefill(request);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }
        if (!dialog.addressValid())
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("地址不是合法的非零十六进制数。")));
            return;
        }
        const ksword::kvm::KvmWatchTarget watchTarget = dialog.target();
        if (watchTarget.access == 0UL)
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("请至少选择一种要监视的访问类型。")));
            return;
        }
        /*
         * 安装是阻塞 IOCTL，必须离开 UI 线程。
         *
         * QPointer 守着 parent：安装期间用户完全可以把那一页关掉，而结果回来
         * 时往一个已经析构的窗口上弹消息框就是一次崩溃。
         */
        QPointer<QWidget> safeParent(parent);
        const QString label = request.label;
        std::thread([safeParent, watchTarget, label]() {
            const ksword::kvm::KvmWatchResult result =
                ksword::kvm::addWatch(watchTarget);
            QMetaObject::invokeMethod(
                qApp,
                [safeParent, result, label]() {
                    const QString title =
                        text(QStringLiteral("添加内存监视"));
                    // 成功时把"接下来会发生什么"说清楚：这一条不会立刻生效，
                    // 而用户此刻最可能的下一个动作正是去启动常驻。
                    const QString body = result.ok
                        ? text(QStringLiteral("已为 %1 安装内存监视。\n\n监视在启动常驻之后才开始生效；命中一次后会自动解除，届时可在“虚拟化 (KVM) → 内存监视”页查看现场并重新武装。"))
                            .arg(label.isEmpty()
                                ? text(QStringLiteral("该目标"))
                                : label)
                        : result.message;
                    if (safeParent != nullptr)
                    {
                        result.ok
                            ? QMessageBox::information(safeParent, title, body)
                            : QMessageBox::warning(safeParent, title, body);
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }
}
