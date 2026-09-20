// KvmWatch：R-1 内存监视（首次访问归因）的门面实现。
//
// 单独成文件而不是塞进 KvmControl.cpp：这一组是唯一需要拉进 Windows 模块枚举
// 的门面成员，而 KvmControl.cpp 至今只依赖 ArkDriverClient 与 Qt。把
// NtQuerySystemInformation 拖进那个翻译单元，等于让每一个只想读 KVM 状态的
// 调用点都跟着背上它。

#include "KvmControl.h"

#include "../Internationalization/LanguageManager.h"

#include <QDir>
#include <QFile>
#include <QHash>
#include <QLibrary>
#include <QMutex>
#include <QMutexLocker>
#include <QPair>

#include <algorithm>
#include <iterator>
#include <vector>

namespace ksword::kvm
{
    namespace
    {
        /* SystemModuleInformation。ntdll 不导出这个常量，只能写死。 */
        constexpr unsigned long kSystemModuleInformationClass = 11UL;

        /*
         * RTL_PROCESS_MODULE_INFORMATION 的本地复刻。
         *
         * 不从 WDK 头里取：这是用户态代码，而那个结构在公开的用户态 SDK 里没有
         * 定义。字段布局自 Windows XP 起未变，越界风险由下面按 count 逐行读、
         * 且缓冲区长度由内核自己回报来兜住。
         */
        struct SystemModuleRow
        {
            void* section;
            void* mappedBase;
            void* imageBase;
            unsigned long imageSize;
            unsigned long flags;
            unsigned short loadOrderIndex;
            unsigned short initOrderIndex;
            unsigned short loadCount;
            unsigned short fileNameOffset;
            unsigned char fullPathName[256];
        };

        struct SystemModuleList
        {
            unsigned long count;
            SystemModuleRow rows[1];
        };

        using NtQuerySystemInformationFunction =
            long(__stdcall*)(unsigned long, void*, unsigned long, unsigned long*);

        /*
         * 把一个 PID 翻译成映像名。
         *
         * 只做补充显示，判据始终是 PID 本身：驱动归因发生在一个时刻，这次查询
         * 发生在另一个时刻，而 PID 会被回收。名字取不到时返回空串，让调用方
         * 只显示 PID —— 一个错误的进程名比没有名字更误导。
         *
         * 用 QueryFullProcessImageNameW 而不是 GetModuleFileNameEx：它只要
         * PROCESS_QUERY_LIMITED_INFORMATION，因此对受保护进程也问得出名字，而
         * 恰恰是那一类进程最值得出现在归因结果里。
         */
        QString processImageNameForPid(const unsigned long processId)
        {
            if (processId == 0UL)
            {
                return QString();
            }
            const HANDLE process = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (process == nullptr)
            {
                return QString();
            }
            wchar_t buffer[MAX_PATH] = {};
            DWORD length = static_cast<DWORD>(std::size(buffer));
            const BOOL ok = ::QueryFullProcessImageNameW(
                process, 0, buffer, &length);
            ::CloseHandle(process);
            if (ok == FALSE || length == 0UL)
            {
                return QString();
            }
            const QString fullPath = QString::fromWCharArray(
                buffer, static_cast<int>(length));
            const int separator = fullPath.lastIndexOf(QLatin1Char('\\'));
            return separator >= 0 ? fullPath.mid(separator + 1) : fullPath;
        }

        QString ruleStatusText(const unsigned long status)
        {
            switch (status)
            {
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST:
                return ks::i18n::sourceText(QStringLiteral("请求不合法"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED:
                return ks::i18n::sourceText(QStringLiteral("需要显式确认"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED:
                return ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND:
                return ks::i18n::sourceText(QStringLiteral("没有这条监视"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL:
                return ks::i18n::sourceText(QStringLiteral("规则表已满"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED:
                return ks::i18n::sourceText(QStringLiteral("目标页无法拆成 4 KiB 叶"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL:
                return ks::i18n::sourceText(QStringLiteral("部分处理器未能完成失效"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED:
                return ks::i18n::sourceText(QStringLiteral("这条处置当前未实现"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE:
                return ks::i18n::sourceText(QStringLiteral("这台机器上无法安全实现该处置"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT:
                return ks::i18n::sourceText(QStringLiteral("这一页已经被别的 EPT 机制占着"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN:
                return ks::i18n::sourceText(QStringLiteral("常驻运行中：EPT 规则表在常驻期间冻结，安装与撤销都要先停止常驻"));
            default:
                break;
            }
            return ks::i18n::sourceText(QStringLiteral("协议状态 %1")).arg(status);
        }

        /* 把一行协议快照翻译成 UI 结构。 */
        KvmWatchEntry toWatchEntry(const KSWORD_ARK_HVM_EPT_WATCH_ROW& row)
        {
            KvmWatchEntry entry;
            entry.watchId = row.watchId;
            entry.state = row.state;
            entry.requestedAccess = row.requestedAccess;
            entry.effectiveAccess = row.effectiveAccess;
            entry.addressKind = row.addressKind;
            entry.hitCount = row.hitCount;
            entry.lastHitSequence = row.lastHitSequence;
            entry.lastHitStatus = row.lastHitStatus;
            entry.armedGeneration = row.armedGeneration;
            entry.requestedAddress = row.requestedAddress;
            entry.requestedLength = row.requestedLength;
            entry.physicalPage = row.physicalPage;
            entry.pageCount = row.pageCount;
            entry.lastHitRip = row.lastHitRip;
            entry.lastHitGuestLinearAddress = row.lastHitGuestLinearAddress;
            entry.lastHitGuestPhysicalAddress = row.lastHitGuestPhysicalAddress;
            entry.lastHitCr3 = row.lastHitCr3;
            entry.lastHitRsp = row.lastHitRsp;
            entry.lastHitTimestamp = row.lastHitTimestamp;
            entry.lastHitProcessorGroup = row.lastHitProcessorGroup;
            entry.lastHitProcessorNumber = row.lastHitProcessorNumber;
            entry.lastHitGuestLinearValid = row.lastHitGuestLinearValid != 0U;
            entry.lastHitRangeMatch = row.lastHitRangeMatch != 0UL;
            return entry;
        }

        /* 把驱动响应翻译成 UI 可直接展示的结论。 */
        KvmWatchResult toWatchResult(
            const ksword::ark::HvmEptRuleResult& result,
            const QString& actionName)
        {
            KvmWatchResult watch;
            watch.protocolStatus = result.response.status;
            watch.lastStatus = result.response.lastStatus;
            watch.conflictOwnerId = result.response.conflictOwnerId;
            watch.conflictOwnerKind = result.response.conflictOwnerKind;
            watch.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
            if (result.io.ok)
            {
                // 表在成功与失败时都回填：失败也要让调用方看见现在装着什么，
                // 否则"表已满"这类拒绝只剩一个数字，没法判断该撤哪一条。
                const unsigned long rows =
                    result.response.returnedWatchRows <=
                        KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS
                        ? result.response.returnedWatchRows
                        : KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS;
                for (unsigned long index = 0; index < rows; ++index)
                {
                    watch.watches.append(
                        toWatchEntry(result.response.watchRows[index]));
                }
                // 单条操作把它那一行也带上，调用方不必为了看结果再查一次。
                if (rows == 0 && result.response.watch.watchId != 0)
                {
                    watch.watches.append(toWatchEntry(result.response.watch));
                }
                watch.watchCount = result.response.watchRowCount != 0
                    ? result.response.watchRowCount
                    : static_cast<unsigned long>(watch.watches.size());
            }
            if (watch.ok)
            {
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return watch;
            }
            if (!result.io.ok && result.unsupported)
            {
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return watch;
            }
            if (result.response.status ==
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT)
            {
                // 冲突要指名道姓：只说"冲突"的话，用户没法知道该先撤哪一个。
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：%2。请先移除它，再安装内存监视。"))
                    .arg(actionName)
                    .arg(describeWatchConflict(
                        result.response.conflictOwnerKind,
                        result.response.conflictOwnerId));
                return watch;
            }
            watch.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(ruleStatusText(result.response.status));
            return watch;
        }

        /*
         * 把 NT 路径转成能直接打开的 Win32 路径。
         *
         * SystemModuleInformation 回的是内核视角的路径：ntoskrnl 是
         * `\SystemRoot\system32\ntoskrnl.exe`，第三方驱动多半是
         * `\??\C:\...`，少数直接就是 `\Windows\...`。三种都要认，认不出就
         * 返回空串让调用方安静放弃 —— 拿一个猜出来的路径去打开另一个文件，
         * 解析出的符号会是另一个模块的。
         */
        QString toWin32Path(const QString& ntPath)
        {
            QString path = ntPath;
            if (path.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
            {
                return path.mid(4);
            }
            if (path.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
            {
                return QDir::toNativeSeparators(
                    QString::fromLocal8Bit(qgetenv("SystemRoot")) +
                    path.mid(11));
            }
            if (path.startsWith(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive))
            {
                return QDir::toNativeSeparators(
                    QString::fromLocal8Bit(qgetenv("SystemDrive")) + path);
            }
            // 已经是 `C:\...` 形式的直接用。
            if (path.size() > 2 && path[1] == QLatin1Char(':'))
            {
                return path;
            }
            return QString();
        }

        /* 一个模块的导出表：RVA 升序，供二分查找最近的前驱。 */
        struct ExportTable
        {
            bool valid = false;
            QVector<QPair<quint32, QString>> entries;
        };

        /*
         * 从**磁盘映像**解析导出表。
         *
         * 不去读内存里的那一份：读内存要走 R-1 内存接口、要写权限门、而且正在
         * 排查的场景里内存那一份恰恰是可能被改过的。磁盘映像回答的是"这个函数
         * 本来叫什么"，那才是归因需要的。
         */
        ExportTable loadExportTable(const QString& ntPath)
        {
            ExportTable table;
            const QString win32Path = toWin32Path(ntPath);
            if (win32Path.isEmpty())
            {
                return table;
            }
            QFile file(win32Path);
            if (!file.open(QIODevice::ReadOnly))
            {
                return table;
            }
            const QByteArray image = file.readAll();
            file.close();
            const auto* const base =
                reinterpret_cast<const unsigned char*>(image.constData());
            const qsizetype size = image.size();
            if (size < static_cast<qsizetype>(sizeof(IMAGE_DOS_HEADER)))
            {
                return table;
            }
            const auto* const dos =
                reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
                dos->e_lfanew <= 0 ||
                dos->e_lfanew + static_cast<LONG>(sizeof(IMAGE_NT_HEADERS64)) >
                    static_cast<LONG>(size))
            {
                return table;
            }
            const auto* const nt =
                reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                return table;
            }
            const IMAGE_DATA_DIRECTORY& directory =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (directory.VirtualAddress == 0 || directory.Size == 0)
            {
                return table;
            }
            // 磁盘映像按 FileAlignment 排布，RVA 必须逐节翻成文件偏移。
            const auto* const sections = IMAGE_FIRST_SECTION(nt);
            const auto rvaToOffset = [&](const quint32 rva) -> qsizetype {
                for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index)
                {
                    const IMAGE_SECTION_HEADER& section = sections[index];
                    if (rva >= section.VirtualAddress &&
                        rva < section.VirtualAddress + section.SizeOfRawData)
                    {
                        return static_cast<qsizetype>(
                            section.PointerToRawData + (rva - section.VirtualAddress));
                    }
                }
                return -1;
            };
            const qsizetype directoryOffset = rvaToOffset(directory.VirtualAddress);
            if (directoryOffset < 0 ||
                directoryOffset + static_cast<qsizetype>(sizeof(IMAGE_EXPORT_DIRECTORY)) > size)
            {
                return table;
            }
            const auto* const exports =
                reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + directoryOffset);
            const qsizetype namesOffset = rvaToOffset(exports->AddressOfNames);
            const qsizetype ordinalsOffset = rvaToOffset(exports->AddressOfNameOrdinals);
            const qsizetype functionsOffset = rvaToOffset(exports->AddressOfFunctions);
            if (namesOffset < 0 || ordinalsOffset < 0 || functionsOffset < 0)
            {
                return table;
            }
            const auto* const nameRvas =
                reinterpret_cast<const quint32*>(base + namesOffset);
            const auto* const ordinals =
                reinterpret_cast<const quint16*>(base + ordinalsOffset);
            const auto* const functionRvas =
                reinterpret_cast<const quint32*>(base + functionsOffset);
            table.entries.reserve(static_cast<int>(exports->NumberOfNames));
            for (quint32 index = 0; index < exports->NumberOfNames; ++index)
            {
                const qsizetype nameOffset = rvaToOffset(nameRvas[index]);
                if (nameOffset < 0 || nameOffset >= size)
                {
                    continue;
                }
                const quint16 ordinal = ordinals[index];
                if (ordinal >= exports->NumberOfFunctions)
                {
                    continue;
                }
                const quint32 functionRva = functionRvas[ordinal];
                if (functionRva == 0)
                {
                    continue;
                }
                const char* const name =
                    reinterpret_cast<const char*>(base + nameOffset);
                const qsizetype maximum = size - nameOffset;
                qsizetype length = 0;
                while (length < maximum && name[length] != '\0')
                {
                    ++length;
                }
                table.entries.append(
                    { functionRva, QString::fromLatin1(name, static_cast<int>(length)) });
            }
            std::sort(table.entries.begin(), table.entries.end(),
                [](const QPair<quint32, QString>& left,
                   const QPair<quint32, QString>& right) {
                    return left.first < right.first;
                });
            table.valid = !table.entries.isEmpty();
            return table;
        }

        /*
         * 按模块路径缓存导出表。
         *
         * 监视表每刷新一次就会对每一条命中做一次归因，而内核映像动辄几 MB；
         * 不缓存的话一次刷新要重读、重解析同一份 ntoskrnl 十几遍。模块的磁盘
         * 映像在一次会话内不会变，缓存是安全的。
         */
        const ExportTable& cachedExportTable(const QString& ntPath)
        {
            static QHash<QString, ExportTable> cache;
            static QMutex mutex;
            QMutexLocker locker(&mutex);
            auto found = cache.find(ntPath);
            if (found == cache.end())
            {
                found = cache.insert(ntPath, loadExportTable(ntPath));
            }
            return found.value();
        }

        /* 写权限关闭时统一拒绝，且不发起任何 IOCTL。 */
        KvmWatchResult denyWatchWithoutWriteAccess(const QString& actionName)
        {
            KvmWatchResult watch;
            watch.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return watch;
        }
    }

    KvmWatchResult listWatches()
    {
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY;
        const auto result = client.controlHvmEptWatch(request);
        return toWatchResult(
            result,
            ks::i18n::sourceText(QStringLiteral("读取内存监视")));
    }

    KvmWatchResult addWatch(const KvmWatchTarget& target)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("安装内存监视"));
        if (!isWriteAccessEnabled())
        {
            return denyWatchWithoutWriteAccess(actionName);
        }
        if (target.access == 0UL ||
            (target.access &
                ~(KSWORD_ARK_HVM_EPT_ACCESS_READ |
                  KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
                  KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) != 0UL)
        {
            KvmWatchResult watch;
            watch.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：至少要选一种访问类型。"))
                .arg(actionName);
            return watch;
        }
        unsigned long long physicalAddress = target.address;
        if (target.virtualAddress)
        {
            // 翻译一次并就此定死。
            //
            // 这条 watch 从此绑定在**这一刻**解析出来的物理页上，之后 guest 把
            // 同一个 VA 重映射到别处也不会跟过去。这不是遗漏：跟踪重映射要监视
            // guest 页表本身，那是另一个数量级的机制。这里能做的是把绑定的时刻
            // 和结果如实记下来，让界面之后能检测出分歧并说出来。
            const KvmMemoryResult translated = translate(0, target.address);
            if (!translated.ok || translated.physicalAddress == 0)
            {
                KvmWatchResult watch;
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：这个内核虚拟地址当前翻译不出物理页（%2）。"))
                    .arg(actionName)
                    .arg(translated.message);
                return watch;
            }
            physicalAddress = translated.physicalAddress;
        }
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
        request.requestedAccess = target.access;
        request.addressKind = target.virtualAddress
            ? KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
            : KSWORD_ARK_HVM_WATCH_ADDRESS_PHYSICAL;
        // 实际监视的永远是整页；请求的地址与长度另外记，不参与对齐。
        request.physicalPage = physicalAddress & ~0xFFFULL;
        request.requestedAddress = target.address;
        request.requestedLength = target.length;
        const auto result = client.controlHvmEptWatch(request);
        return toWatchResult(result, actionName);
    }

    KvmWatchResult rearmWatch(const unsigned long watchId)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("重新武装内存监视"));
        if (!isWriteAccessEnabled())
        {
            return denyWatchWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_REARM;
        request.watchId = watchId;
        const auto result = client.controlHvmEptWatch(request);
        return toWatchResult(result, actionName);
    }

    KvmWatchResult removeWatch(const unsigned long watchId)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("移除内存监视"));
        if (!isWriteAccessEnabled())
        {
            return denyWatchWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_REMOVE;
        request.watchId = watchId;
        const auto result = client.controlHvmEptWatch(request);
        return toWatchResult(result, actionName);
    }

    KvmWatchAttribution attributeKernelAddress(const unsigned long long address)
    {
        KvmWatchAttribution attribution;
        static const auto query =
            reinterpret_cast<NtQuerySystemInformationFunction>(
                QLibrary::resolve(
                    QStringLiteral("ntdll"),
                    "NtQuerySystemInformation"));

        if (query == nullptr ||
            address == 0)
        {
            // 解析不出来是一条结论，不是一次失败：调用方据此显示"未知可执行
            // 区域"并给出打开内存/反汇编的入口，而不是只写一个 Unknown。
            return attribution;
        }
        unsigned long needed = 0UL;
        // 先问长度。模块表会变，所以多要一截余量再重试一次，而不是循环到成功
        // ——在一个每秒都可能加载驱动的系统上，那种循环没有终止保证。
        (void)query(kSystemModuleInformationClass, nullptr, 0UL, &needed);
        if (needed == 0UL)
        {
            return attribution;
        }
        std::vector<unsigned char> buffer;
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            buffer.assign(needed + 0x4000U, 0U);
            unsigned long written = 0UL;
            const long status = query(
                kSystemModuleInformationClass,
                buffer.data(),
                static_cast<unsigned long>(buffer.size()),
                &written);
            if (status >= 0)
            {
                break;
            }
            if (attempt == 1)
            {
                return attribution;
            }
            needed = written != 0UL ? written : needed * 2U;
        }
        const auto* const list =
            reinterpret_cast<const SystemModuleList*>(buffer.data());
        const unsigned long count = list->count;
        const size_t capacity =
            (buffer.size() - sizeof(unsigned long)) / sizeof(SystemModuleRow);
        const unsigned long bounded = count <= capacity
            ? count
            : static_cast<unsigned long>(capacity);
        for (unsigned long index = 0; index < bounded; ++index)
        {
            const SystemModuleRow& row = list->rows[index];
            const auto base =
                reinterpret_cast<unsigned long long>(row.imageBase);
            if (row.imageSize == 0UL ||
                address < base ||
                address >= base + row.imageSize)
            {
                continue;
            }
            attribution.resolved = true;
            attribution.moduleBase = base;
            attribution.moduleSize = row.imageSize;
            attribution.relativeAddress = address - base;
            // fullPathName 是 ANSI 的 NT 路径，末尾保证有零；fileNameOffset
            // 指向其中的文件名部分。
            const auto* const path =
                reinterpret_cast<const char*>(row.fullPathName);
            const size_t limit = sizeof(row.fullPathName);
            size_t length = 0;
            while (length < limit && path[length] != '\0')
            {
                ++length;
            }
            attribution.modulePath = QString::fromLatin1(
                path, static_cast<int>(length));
            attribution.moduleName = row.fileNameOffset < length
                ? QString::fromLatin1(
                    path + row.fileNameOffset,
                    static_cast<int>(length - row.fileNameOffset))
                : attribution.modulePath;
            /*
             * 再往下一层：找这个 RVA 前面最近的导出符号。
             *
             * 找不到就留空，调用方只显示 `module.sys+0xRVA` —— 一个错误的函数名
             * 比没有名字更难纠正，因为它会让人去读一段根本不相干的代码。
             */
            {
                const ExportTable& table = cachedExportTable(attribution.modulePath);
                if (table.valid &&
                    attribution.relativeAddress <= 0xFFFFFFFFULL)
                {
                    const quint32 rva =
                        static_cast<quint32>(attribution.relativeAddress);
                    // 第一个 > rva 的位置，它前面那个就是最近的前驱。
                    const auto upper = std::upper_bound(
                        table.entries.cbegin(), table.entries.cend(), rva,
                        [](const quint32 value, const QPair<quint32, QString>& entry) {
                            return value < entry.first;
                        });
                    if (upper != table.entries.cbegin())
                    {
                        const auto& entry = *(upper - 1);
                        attribution.symbolName = entry.second;
                        attribution.symbolOffset = rva - entry.first;
                    }
                }
            }
            break;
        }
        return attribution;
    }

    QString toWin32ModulePath(const QString& ntPath)
    {
        return toWin32Path(ntPath);
    }

    KvmProcessAttribution attributeProcessByCr3(
        const unsigned long long directoryBase)
    {
        KvmProcessAttribution attribution;
        if (directoryBase == 0ULL)
        {
            // 没有 CR3 可归。这与"归不到"是两件事：前者是没问，后者是问过了。
            return attribution;
        }

        ksword::ark::DriverClient client;
        const auto result = client.resolveHvmDirectoryBase(directoryBase);
        attribution.scannedProcesses = result.response.resolvedScannedProcesses;
        if (!result.io.ok)
        {
            // IOCTL 本身没通：驱动不在、句柄开不出来、协议版本对不上。
            attribution.kind = KvmProcessAttributionKind::Failed;
            return attribution;
        }
        if (result.response.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK &&
            result.response.resolvedProcessId != 0UL)
        {
            attribution.kind = KvmProcessAttributionKind::Resolved;
            attribution.processId = result.response.resolvedProcessId;
            attribution.imageName = processImageNameForPid(
                result.response.resolvedProcessId);
            return attribution;
        }
        if (result.response.status ==
            KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND)
        {
            /*
             * 扫过了没匹配上。
             *
             * 这里**必须**看扫描数而不是只看状态码：一个都没扫成时驱动回的是
             * PROCESS_LOOKUP_FAILED，但一个"扫了 0 个所以没找到"的实现同样会
             * 回 NOT_FOUND，而那两句话要人做的事相反。多核一道判据，让这条
             * 分支自己站得住。
             */
            attribution.kind = attribution.scannedProcesses != 0UL
                ? KvmProcessAttributionKind::NotFound
                : KvmProcessAttributionKind::Failed;
            return attribution;
        }
        attribution.kind = KvmProcessAttributionKind::Failed;
        return attribution;
    }

    QString describeProcessAttribution(const KvmProcessAttribution& attribution)
    {
        switch (attribution.kind)
        {
        case KvmProcessAttributionKind::Resolved:
            return attribution.imageName.isEmpty()
                ? ks::i18n::sourceText(
                      QStringLiteral("PID %1（由当前进程快照解析，不是命中那一刻的事实）"))
                      .arg(attribution.processId)
                : ks::i18n::sourceText(
                      QStringLiteral("%1 (PID %2)（由当前进程快照解析，不是命中那一刻的事实）"))
                      .arg(attribution.imageName)
                      .arg(attribution.processId);
        case KvmProcessAttributionKind::NotFound:
            return ks::i18n::sourceText(
                QStringLiteral("扫过 %1 个进程都没有这个地址空间——它多半已经退出了"))
                .arg(attribution.scannedProcesses);
        case KvmProcessAttributionKind::Failed:
            return ks::i18n::sourceText(
                QStringLiteral("这次归因没跑起来，一个进程都没问成"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("命中现场没有记下地址空间"));
    }

    QString describeWatchState(const unsigned long state)
    {
        switch (state)
        {
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED:
            return ks::i18n::sourceText(QStringLiteral("监视中"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED:
            return ks::i18n::sourceText(QStringLiteral("正在处理命中"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED:
            return ks::i18n::sourceText(QStringLiteral("已命中并解除"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED:
            return ks::i18n::sourceText(QStringLiteral("已失效，需重新武装"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED:
            return ks::i18n::sourceText(QStringLiteral("安装失败"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未武装"));
    }

    QString describeWatchAccess(const unsigned long access)
    {
        QStringList parts;
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL)
        {
            parts << ks::i18n::sourceText(QStringLiteral("读"));
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL)
        {
            parts << ks::i18n::sourceText(QStringLiteral("写"));
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL)
        {
            parts << ks::i18n::sourceText(QStringLiteral("执行"));
        }
        if (parts.isEmpty())
        {
            return ks::i18n::sourceText(QStringLiteral("无"));
        }
        return parts.join(ks::i18n::sourceText(QStringLiteral(" + ")));
    }

    QString describeWatchConflict(
        const unsigned long ownerKind,
        const unsigned long ownerId)
    {
        switch (ownerKind)
        {
        case KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW:
            return ks::i18n::sourceText(
                QStringLiteral("这一页已经被 EPT 分离视图 #%1 占着")).arg(ownerId);
        case KSWORD_ARK_HVM_WATCH_CONFLICT_RULE:
            return ks::i18n::sourceText(
                QStringLiteral("这一页已经被 EPT 规则 #%1 占着")).arg(ownerId);
        case KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH:
            return ks::i18n::sourceText(
                QStringLiteral("这一页已经被内存监视 #%1 占着")).arg(ownerId);
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("这一页已经被别的 EPT 机制占着"));
    }
}
