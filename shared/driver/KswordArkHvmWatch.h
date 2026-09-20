/*
 * KswordArkHvmWatch.h
 *
 * 首次访问监视（EPT WATCH_ONCE）里，算错了**不会报错**、只会安静地做错事的那
 * 几件事。收录标准与 KswordArkHvmEptSwitch.h 一致：纯输入到输出、无副作用、
 * 错了很难当场发现。
 *
 * ------------------------------------------------------------------
 * 这套机制是什么
 * ------------------------------------------------------------------
 *
 * 把目标页的某类权限拿掉，等下一次访问撞上来，在 VM-exit 里记下现场，然后把
 * 权限**永久**恢复、失效翻译、RIP 不推进就 VMRESUME —— 原指令重执行并正常
 * 完成，常驻继续。它等于「ALLOW_ONCE 去掉再收回那一步」，所以不需要 monitor
 * trap flag，也就能在没有 MTF 的嵌套靶机上工作。
 *
 * ------------------------------------------------------------------
 * 为什么这几件事必须在编译机上证明
 * ------------------------------------------------------------------
 *
 * 三类错误都没有诊断面：
 *
 *   - **权限归一化算错**：EPT 架构上不存在「可写但不可读」的叶项，也不是每台
 *     处理器都能编码「仅执行」。把用户请求的掩码直接写进叶项，得到的是一张
 *     非法叶——表现是某次访问触发 EPT misconfiguration（exit reason 49），
 *     那个退出只告诉你有一位不对，不告诉你是哪一位。而如果归一化过了头，
 *     表现更糟：监视范围悄悄比用户以为的更大，没有任何提示。
 *
 *   - **多核首次命中的决议算错**：两个处理器同时撞上同一页时，如果两个都认为
 *     自己是第一次，用户会看到两条互相矛盾的「第一次访问」；如果输的那一方
 *     只是原地 VMRESUME 而不修复自己的视图，它会在恢复传播到自己之前一直
 *     重复违规——那是一个没有任何错误码的活锁。两种结局都不会打印任何东西。
 *
 *   - **范围判定算错**：EPT 监视的是整页，而用户关心的往往是页里的几个字节。
 *     判错的后果不是崩溃，是一句**读起来完全正确、实际可能完全不相干**的
 *     结论：「你的目标被访问了」。这类错误只会让人查错方向，不会让人发现。
 *
 * 本头文件是 C 与 C++ 共用的：驱动里的 VM-exit 路径和编译机上的离线测试链接
 * 同一份实现，所以测试证明的就是内核里跑的那一份。
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* 与 KswordArkHvmIoctl.h 的 KSWORD_ARK_HVM_EPT_ACCESS_* 逐位相同。 */
#define KSW_HVM_WATCH_ACCESS_READ    0x00000001UL
#define KSW_HVM_WATCH_ACCESS_WRITE   0x00000002UL
#define KSW_HVM_WATCH_ACCESS_EXECUTE 0x00000004UL

/* 与 hvm_internal.h 的 KSW_EPT_* 逐位相同。 */
#define KSW_HVM_WATCH_LEAF_READ    0x1ULL
#define KSW_HVM_WATCH_LEAF_WRITE   0x2ULL
#define KSW_HVM_WATCH_LEAF_EXECUTE 0x4ULL

/* 与 KswordArkHvmIoctl.h 的 KSWORD_ARK_HVM_EPT_WATCH_STATE_* 逐值相同。 */
#define KSW_HVM_WATCH_STATE_NONE        0UL
#define KSW_HVM_WATCH_STATE_ARMED       1UL
#define KSW_HVM_WATCH_STATE_TRIGGERED   2UL
#define KSW_HVM_WATCH_STATE_DISARMED    3UL
#define KSW_HVM_WATCH_STATE_INVALIDATED 4UL
#define KSW_HVM_WATCH_STATE_FAULTED     5UL

/*
 * 一次命中的处置计划。
 *
 * 三个位分别回答三个独立的问题，而不是一个「成功/失败」：
 *
 *   Accepted     这个状态能不能由命中路径继续。不能时调用方必须 fail-closed，
 *                而不是猜一个处置。
 *   OwnsFirstHit 这个处理器是不是唯一的 first-hit owner。只有它记录证据、
 *                推进生命周期、发布事件。
 *   MustRepair   要不要把这一页的权限恢复并失效自己的上下文。
 *
 * 关键在于 MustRepair 与 OwnsFirstHit **不是同一件事**：输掉原子转换的处理器
 * 同样要修复自己那一份视图。只有赢家修复的话，输家会在赢家的写传播到自己之前
 * 反复撞同一条指令——一个不打印任何东西的活锁。
 */
typedef struct _KSW_HVM_WATCH_HIT_PLAN
{
    unsigned char Accepted;
    unsigned char OwnsFirstHit;
    unsigned char MustRepair;
    unsigned char Reserved;
} KSW_HVM_WATCH_HIT_PLAN;

/*
 * 把用户请求的访问掩码归一化成一个**架构上合法**的 EPT 拒绝掩码。
 *
 * 两条硬约束：
 *   1. 传统 EPT 不允许 W=1 而 R=0。所以拿掉读就必须连写一起拿掉——否则剩下的
 *      叶项是 R=0/W=1，非法。
 *   2. 仅执行（execute-only）叶项不是每台处理器都支持。不支持时，拿掉读还必须
 *      连执行一起拿掉，否则剩下 R=0/W=0/X=1，同样非法。
 *
 * 返回值必然是输入的超集：归一化只会让监视范围变大，不会变小。调用方必须把
 * 请求值和返回值都留着——只显示其中一个，要么替用户改了他的请求，要么谎称
 * 监视得比实际更细。
 */
static __inline unsigned long
KswordArkHvmWatchNormalizeAccess(
    unsigned long RequestedAccess,
    int ExecuteOnlySupported
    )
{
    unsigned long effective = RequestedAccess &
        (KSW_HVM_WATCH_ACCESS_READ |
         KSW_HVM_WATCH_ACCESS_WRITE |
         KSW_HVM_WATCH_ACCESS_EXECUTE);

    /* 没有任何合法位时原样返回：合法性由调用方在更早一步拒绝。 */
    if (effective == 0UL) {
        return 0UL;
    }
    if ((effective & KSW_HVM_WATCH_ACCESS_READ) != 0UL) {
        /* 阻止架构上不存在的「可写不可读」状态。 */
        effective |= KSW_HVM_WATCH_ACCESS_WRITE;
        if (!ExecuteOnlySupported) {
            /* 这台处理器编码不出仅执行叶项，只能退化成整页不可访问。 */
            effective |= KSW_HVM_WATCH_ACCESS_EXECUTE;
        }
    }
    return effective;
}

/*
 * 按一个拒绝掩码从叶项里拿掉权限位。
 *
 * 只清位、不设位：这个函数表达的是「拿掉」，任何"顺手补一位"都会让一条监视
 * 悄悄放开它本该拦住的访问。
 */
static __inline unsigned long long
KswordArkHvmWatchApplyDenial(
    unsigned long long Leaf,
    unsigned long DeniedAccess
    )
{
    unsigned long long value = Leaf;

    if ((DeniedAccess & KSW_HVM_WATCH_ACCESS_READ) != 0UL) {
        value &= ~KSW_HVM_WATCH_LEAF_READ;
    }
    if ((DeniedAccess & KSW_HVM_WATCH_ACCESS_WRITE) != 0UL) {
        value &= ~KSW_HVM_WATCH_LEAF_WRITE;
    }
    if ((DeniedAccess & KSW_HVM_WATCH_ACCESS_EXECUTE) != 0UL) {
        value &= ~KSW_HVM_WATCH_LEAF_EXECUTE;
    }
    return value;
}

/*
 * 把一张叶项恢复成「没有任何拒绝」的基线。
 *
 * 只动 R/W/X 三位，其余位（页帧、内存类型、大页位、suppress-#VE）原样保留 ——
 * 恢复权限时顺手改掉内存类型，后果是一次 EPT misconfiguration，而那个退出
 * 不会告诉你是哪一位不对。
 */
static __inline unsigned long long
KswordArkHvmWatchRestoreLeaf(
    unsigned long long Leaf
    )
{
    return Leaf |
        KSW_HVM_WATCH_LEAF_READ |
        KSW_HVM_WATCH_LEAF_WRITE |
        KSW_HVM_WATCH_LEAF_EXECUTE;
}

/*
 * 决定这一次命中由谁承担。
 *
 * PreviousState 是原子转换 ARMED -> TRIGGERED 之前读到的值：
 *
 *   ARMED        这个处理器赢了，它是唯一的 first-hit owner。
 *   TRIGGERED    别的处理器正在处理同一次首触；本核只修复自己的视图。
 *   DISARMED     首触已经处理完，本核撞上的是一份还没失效的旧翻译；同样只修复。
 *   其余         命中路径无法解释的状态（从未武装、已失效、安装失败）。既然
 *                解释不了，就不能替它挑一个处置 —— 交给 fail-closed。
 */
static __inline KSW_HVM_WATCH_HIT_PLAN
KswordArkHvmWatchPlanHit(
    unsigned long PreviousState
    )
{
    KSW_HVM_WATCH_HIT_PLAN plan;

    plan.Accepted = 0U;
    plan.OwnsFirstHit = 0U;
    plan.MustRepair = 0U;
    plan.Reserved = 0U;
    if (PreviousState == KSW_HVM_WATCH_STATE_ARMED) {
        plan.Accepted = 1U;
        plan.OwnsFirstHit = 1U;
        plan.MustRepair = 1U;
        return plan;
    }
    if (PreviousState == KSW_HVM_WATCH_STATE_TRIGGERED ||
        PreviousState == KSW_HVM_WATCH_STATE_DISARMED) {
        /*
         * 输家也要修。只是 VMRESUME 的话，它会在赢家的恢复传播到自己之前
         * 一直重复违规；那是一个没有错误码、没有日志、也不会自己停下来的活锁。
         */
        plan.Accepted = 1U;
        plan.MustRepair = 1U;
        return plan;
    }
    return plan;
}

/*
 * 判断一次命中是否落在用户真正关心的那一段字节里。
 *
 * 这是**归因的细化，不是过滤**：无论落没落在范围内，命中都要报出来 —— 硬件
 * 监视的是整页，说成别的就是在描述一件没有发生的事。
 *
 * GlaValid 为假时一律返回 0，并且调用方必须把这一态显示成「无法判断」而不是
 * 「不在范围内」：处理器没报告线性地址，和它报告了一个不在范围内的地址，是
 * 两个不同的事实。
 */
static __inline int
KswordArkHvmWatchRangeMatch(
    int GlaValid,
    unsigned long long GuestLinearAddress,
    unsigned long long RequestedAddress,
    unsigned long long RequestedLength
    )
{
    if (!GlaValid ||
        RequestedLength == 0ULL) {
        return 0;
    }
    /*
     * 拒绝会回绕的区间，而不是让它匹配上半个地址空间。
     *
     * 判据写成 (length - 1) > (~0 - base) 而不是 base > ~0 - length：后者会把
     * **恰好顶到地址空间末尾**的区间也一并拒掉（base=0xFF..F8、length=8 时
     * end 正好溢出成 0），而那是一个完全合法的区间。把合法区间判成"不在范围
     * 内"，正是这个功能最不能给出的那一类错答案。length 已经非零，减一不会
     * 下溢。
     */
    if (RequestedLength - 1ULL > ~0ULL - RequestedAddress) {
        return 0;
    }
    /*
     * 用减法比较而不是算出 end 再比：区间已经证明不回绕，而减法在任何输入下
     * 都不会溢出，于是顶到末尾的那一格也能正确落进来。
     */
    if (GuestLinearAddress < RequestedAddress) {
        return 0;
    }
    return (GuestLinearAddress - RequestedAddress) < RequestedLength ? 1 : 0;
}

#ifdef __cplusplus
}
#endif
