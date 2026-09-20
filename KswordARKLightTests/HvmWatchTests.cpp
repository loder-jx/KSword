// 首次访问监视（EPT WATCH_ONCE，shared/driver/KswordArkHvmWatch.h）的离线测试。
//
// 被测的四件事有一个共同点：**算错了不会报错**。
//
//   * 权限归一化算少了，叶项架构非法，表现是一次匿名的 exit reason 49；算多了，
//     监视范围悄悄比用户以为的大，没有任何提示。
//   * 多核首触决议算错，要么出现两条互相矛盾的「第一次访问」，要么输掉竞争的
//     处理器陷进一个没有错误码、也不会自己停下来的活锁。
//   * 叶恢复顺手动了 R/W/X 以外的位，同样只换来一次 exit reason 49。
//   * 范围判定算错，结局不是崩溃，是一句读起来完全正确、实际可能完全不相干的
//     结论：「你的目标被访问了」。
//
// 所以它们只能在编译机上被证明。断言原则与 HvmEptSwitchTests.cpp 一致：
//   * 期望值独立手算写死，绝不从被测函数反算；
//   * 状态机做穷举，不该被接受的状态必须被显式拒绝；
//   * 边界两侧都测，只测一侧等于没测。

#include "TestSupport.h"

#include "../shared/driver/KswordArkHvmWatch.h"

#include <cstdint>

namespace {

// 一张典型的 4 KiB 恒等叶：帧 0x12345000，RWX(0x7)，WB(6<<3 = 0x30)，
// suppress-#VE(bit 63)。低字节 = 0x7|0x30 = 0x37。
constexpr std::uint64_t kLeafRwx = 0x8000000012345037ULL;
// 同一张叶去掉 R/W/X 三位：0x37 & ~0x7 = 0x30。
constexpr std::uint64_t kLeafNoAccess = 0x8000000012345030ULL;

// ---------------------------------------------------------------------------
// 权限归一化
// ---------------------------------------------------------------------------
void TestNormalizeAccess(KswordTests::Suite& suite) {
    // 写与执行不触发任何连带：它们各自是合法的单独拒绝。
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_WRITE, 1) ==
            KSW_HVM_WATCH_ACCESS_WRITE,
        L"watch normalize: write alone stays write (execute-only supported)");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_WRITE, 0) ==
            KSW_HVM_WATCH_ACCESS_WRITE,
        L"watch normalize: write alone stays write (no execute-only)");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_EXECUTE, 1) ==
            KSW_HVM_WATCH_ACCESS_EXECUTE,
        L"watch normalize: execute alone stays execute (execute-only supported)");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_EXECUTE, 0) ==
            KSW_HVM_WATCH_ACCESS_EXECUTE,
        L"watch normalize: execute alone stays execute (no execute-only)");
    // 写+执行同样不触发连带：剩下的叶是 R=1/W=0/X=0，合法。
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(
            KSW_HVM_WATCH_ACCESS_WRITE | KSW_HVM_WATCH_ACCESS_EXECUTE, 0) ==
            (KSW_HVM_WATCH_ACCESS_WRITE | KSW_HVM_WATCH_ACCESS_EXECUTE),
        L"watch normalize: write+execute needs no widening");

    // 读必然带上写：EPT 上不存在 W=1/R=0。
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_READ, 1) ==
            (KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_WRITE),
        L"watch normalize: read widens to read+write with execute-only");
    // 没有仅执行能力时，读还要带上执行，否则剩下 R=0/W=0/X=1，同样非法。
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_READ, 0) ==
            (KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_WRITE |
             KSW_HVM_WATCH_ACCESS_EXECUTE),
        L"watch normalize: read widens to all three without execute-only");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(
            KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_EXECUTE, 1) ==
            (KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_WRITE |
             KSW_HVM_WATCH_ACCESS_EXECUTE),
        L"watch normalize: read+execute widens to all three");

    // 归一化只能扩大，绝不能缩小：逐个组合与输入求交集核对。
    for (unsigned long requested = 1UL; requested <= 7UL; ++requested) {
        for (int executeOnly = 0; executeOnly <= 1; ++executeOnly) {
            const unsigned long effective =
                KswordArkHvmWatchNormalizeAccess(requested, executeOnly);
            suite.expect(
                (effective & requested) == requested,
                L"watch normalize: result is a superset of the request");
            suite.expect(
                (effective & ~7UL) == 0UL,
                L"watch normalize: result carries no bit outside r/w/x");
            // 归一化是幂等的：再归一化一次不能继续变大。
            suite.expect(
                KswordArkHvmWatchNormalizeAccess(effective, executeOnly) ==
                    effective,
                L"watch normalize: idempotent");
            // 结果必须是一个合法的剩余权限组合。RWX 全被拿掉也合法
            //（那是整页不可访问）；非法的只有 R=0 而 W=1。
            const bool readDenied =
                (effective & KSW_HVM_WATCH_ACCESS_READ) != 0UL;
            const bool writeDenied =
                (effective & KSW_HVM_WATCH_ACCESS_WRITE) != 0UL;
            suite.expect(
                !readDenied || writeDenied,
                L"watch normalize: denying read always denies write");
            const bool executeDenied =
                (effective & KSW_HVM_WATCH_ACCESS_EXECUTE) != 0UL;
            suite.expect(
                executeOnly != 0 || !readDenied || executeDenied,
                L"watch normalize: without execute-only, denying read denies execute");
        }
    }

    // 未定义位一律被丢掉，不会被当成第四种权限传下去。
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(0xFFFFFFF8UL, 1) == 0UL,
        L"watch normalize: unknown bits alone normalize to zero");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(
            0xFFFFFFF0UL | KSW_HVM_WATCH_ACCESS_WRITE, 1) ==
            KSW_HVM_WATCH_ACCESS_WRITE,
        L"watch normalize: unknown bits are dropped, known bits survive");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(0UL, 1) == 0UL,
        L"watch normalize: empty request stays empty");
}

// ---------------------------------------------------------------------------
// 叶项算术
// ---------------------------------------------------------------------------
void TestLeafArithmetic(KswordTests::Suite& suite) {
    // 拿掉写只清 bit 1：0x37 & ~0x2 = 0x35。
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, KSW_HVM_WATCH_ACCESS_WRITE) ==
            0x8000000012345035ULL,
        L"watch leaf: denying write clears bit 1 only");
    // 拿掉执行只清 bit 2：0x37 & ~0x4 = 0x33。
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, KSW_HVM_WATCH_ACCESS_EXECUTE) ==
            0x8000000012345033ULL,
        L"watch leaf: denying execute clears bit 2 only");
    // 拿掉读只清 bit 0：0x37 & ~0x1 = 0x36。归一化的责任不在这个函数身上，
    // 它表达的就是"照掩码拿掉"，所以这里**故意**允许一个单独的读拒绝。
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, KSW_HVM_WATCH_ACCESS_READ) ==
            0x8000000012345036ULL,
        L"watch leaf: denying read clears bit 0 only");
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, 7UL) == kLeafNoAccess,
        L"watch leaf: denying all three clears exactly r/w/x");
    // 空掩码不改任何东西。
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, 0UL) == kLeafRwx,
        L"watch leaf: an empty denial changes nothing");
    // 页帧、内存类型、大页位、suppress-#VE 一位都不能动。
    suite.expect(
        (KswordArkHvmWatchApplyDenial(kLeafRwx, 7UL) & ~7ULL) ==
            (kLeafRwx & ~7ULL),
        L"watch leaf: denial never touches a bit outside r/w/x");

    // 恢复只设三位，其余原样。
    suite.expect(
        KswordArkHvmWatchRestoreLeaf(kLeafNoAccess) == kLeafRwx,
        L"watch leaf: restore adds exactly r/w/x back");
    suite.expect(
        KswordArkHvmWatchRestoreLeaf(kLeafRwx) == kLeafRwx,
        L"watch leaf: restoring an unrestricted leaf is idempotent");
    suite.expect(
        (KswordArkHvmWatchRestoreLeaf(kLeafNoAccess) & ~7ULL) ==
            (kLeafNoAccess & ~7ULL),
        L"watch leaf: restore never touches a bit outside r/w/x");
    // 全零叶（未映射槽）恢复后只多出 0x7，不会凭空长出页帧。
    suite.expect(
        KswordArkHvmWatchRestoreLeaf(0ULL) == 7ULL,
        L"watch leaf: restoring an empty entry yields exactly r/w/x");

    // 拿掉再恢复必须回到原值：命中路径正是靠这条性质让原访问能够完成。
    for (unsigned long denied = 0UL; denied <= 7UL; ++denied) {
        suite.expect(
            KswordArkHvmWatchRestoreLeaf(
                KswordArkHvmWatchApplyDenial(kLeafRwx, denied)) == kLeafRwx,
            L"watch leaf: deny then restore round-trips to the original leaf");
    }
}

// ---------------------------------------------------------------------------
// 多核首次命中的决议：穷举全部六个状态
// ---------------------------------------------------------------------------
void TestPlanHit(KswordTests::Suite& suite) {
    // ARMED：唯一的赢家。既记证据也修视图。
    const KSW_HVM_WATCH_HIT_PLAN armed =
        KswordArkHvmWatchPlanHit(KSW_HVM_WATCH_STATE_ARMED);
    suite.expect(armed.Accepted == 1U,
        L"watch plan: armed is accepted");
    suite.expect(armed.OwnsFirstHit == 1U,
        L"watch plan: armed owns the first hit");
    suite.expect(armed.MustRepair == 1U,
        L"watch plan: armed repairs its own view");

    // TRIGGERED：输家。**必须**修视图，但绝不能记第二条"第一次"。
    const KSW_HVM_WATCH_HIT_PLAN triggered =
        KswordArkHvmWatchPlanHit(KSW_HVM_WATCH_STATE_TRIGGERED);
    suite.expect(triggered.Accepted == 1U,
        L"watch plan: triggered is accepted");
    suite.expect(triggered.OwnsFirstHit == 0U,
        L"watch plan: triggered never owns a second first hit");
    suite.expect(triggered.MustRepair == 1U,
        L"watch plan: triggered still repairs its own view");

    // DISARMED：首触已经处理完，本核撞上的是一份没失效的旧翻译。同样只修。
    const KSW_HVM_WATCH_HIT_PLAN disarmed =
        KswordArkHvmWatchPlanHit(KSW_HVM_WATCH_STATE_DISARMED);
    suite.expect(disarmed.Accepted == 1U,
        L"watch plan: disarmed is accepted");
    suite.expect(disarmed.OwnsFirstHit == 0U,
        L"watch plan: disarmed owns no first hit");
    suite.expect(disarmed.MustRepair == 1U,
        L"watch plan: disarmed still repairs its own view");

    // 三个解释不了的状态必须被显式拒绝，交给 fail-closed，而不是猜一个处置。
    const unsigned long rejected[] = {
        KSW_HVM_WATCH_STATE_NONE,
        KSW_HVM_WATCH_STATE_INVALIDATED,
        KSW_HVM_WATCH_STATE_FAULTED,
    };
    for (const unsigned long state : rejected) {
        const KSW_HVM_WATCH_HIT_PLAN plan =
            KswordArkHvmWatchPlanHit(state);
        suite.expect(plan.Accepted == 0U,
            L"watch plan: an unexplainable state is refused");
        suite.expect(plan.OwnsFirstHit == 0U,
            L"watch plan: a refused state owns no first hit");
        suite.expect(plan.MustRepair == 0U,
            L"watch plan: a refused state repairs nothing");
    }
    // 协议之外的数值同样被拒绝，而不是撞进某个分支。
    for (unsigned long state = 6UL; state <= 12UL; ++state) {
        suite.expect(
            KswordArkHvmWatchPlanHit(state).Accepted == 0U,
            L"watch plan: an out-of-protocol state is refused");
    }
    suite.expect(
        KswordArkHvmWatchPlanHit(0xFFFFFFFFUL).Accepted == 0U,
        L"watch plan: the maximum state value is refused");

    // 全局不变式：被接受就一定要修视图；不被接受就一定什么都不做。
    // 这一条是活锁的直接判据——曾经的写法是"只有赢家修"。
    for (unsigned long state = 0UL; state <= 8UL; ++state) {
        const KSW_HVM_WATCH_HIT_PLAN plan =
            KswordArkHvmWatchPlanHit(state);
        suite.expect(
            plan.Accepted == plan.MustRepair,
            L"watch plan: every accepted hit repairs, every refused one does not");
        suite.expect(
            plan.OwnsFirstHit == 0U || plan.Accepted == 1U,
            L"watch plan: ownership implies acceptance");
    }
}

// ---------------------------------------------------------------------------
// 范围判定
// ---------------------------------------------------------------------------
void TestRangeMatch(KswordTests::Suite& suite) {
    constexpr std::uint64_t base = 0xFFFFF80112345678ULL;
    constexpr std::uint64_t length = 8ULL;

    // 区间是半开的：首字节在内，末字节的下一个不在。两侧都要测。
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, base, base, length) == 1,
        L"watch range: the first byte matches");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, base + 7ULL, base, length) == 1,
        L"watch range: the last byte matches");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, base + 8ULL, base, length) == 0,
        L"watch range: one past the end does not match");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, base - 1ULL, base, length) == 0,
        L"watch range: one before the start does not match");

    // 没有有效线性地址时恒不匹配 —— 而调用方必须把这一态显示成"无法判断"，
    // 不是"不在范围内"。两者是不同的事实。
    suite.expect(
        KswordArkHvmWatchRangeMatch(0, base, base, length) == 0,
        L"watch range: an invalid GLA never matches");
    suite.expect(
        KswordArkHvmWatchRangeMatch(0, base + 4ULL, base, length) == 0,
        L"watch range: an invalid GLA never matches even inside the range");

    // 零长度不匹配任何东西：没有请求范围就没有"落在范围内"可言。
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, base, base, 0ULL) == 0,
        L"watch range: a zero-length request matches nothing");

    // 回绕的区间必须被拒绝，而不是匹配上半个地址空间。
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, 0ULL, 0xFFFFFFFFFFFFFFF8ULL, 16ULL) == 0,
        L"watch range: a wrapping range matches nothing at the wrap point");
    suite.expect(
        KswordArkHvmWatchRangeMatch(
            1, 0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFFFFFFFFF8ULL, 16ULL) == 0,
        L"watch range: a wrapping range is refused outright");
    // 刚好顶到地址空间末尾而不回绕的区间仍然成立。
    suite.expect(
        KswordArkHvmWatchRangeMatch(
            1, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFF8ULL, 8ULL) == 1,
        L"watch range: a range ending exactly at the top still matches");

    // 整页请求：页内任意偏移都算命中，页外不算。
    constexpr std::uint64_t page = 0xFFFFF80112345000ULL;
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, page, page, 4096ULL) == 1,
        L"watch range: page start matches a whole-page request");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, page + 4095ULL, page, 4096ULL) == 1,
        L"watch range: page end matches a whole-page request");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, page + 4096ULL, page, 4096ULL) == 0,
        L"watch range: the next page does not match a whole-page request");

    // 同一页里落在请求范围之外 —— 这正是必须与"命中"分开显示的那一态：
    // 硬件监视整页，所以事件照报，但归因上它不是用户点名的那几个字节。
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, page + 0x100ULL, base, length) == 0,
        L"watch range: same page but outside the requested bytes does not match");
}

} // namespace

int RunHvmWatchTests() {
    KswordTests::Suite suite(L"HVM watch");
    TestNormalizeAccess(suite);
    TestLeafArithmetic(suite);
    TestPlanHit(suite);
    TestRangeMatch(suite);
    suite.report();
    return suite.failures();
}
