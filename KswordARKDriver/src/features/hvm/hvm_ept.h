/*++

Module Name:

    hvm_ept.h

Abstract:

    Defines four-KiB EPT split, rule, and transient allow-once handling.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"
#include "hvm_ept_local.h"

/* Preserve one temporary EPT permission grant until monitor-trap exit. */
typedef struct _KSW_HVM_EPT_TRANSIENT
{
    /* Record whether one permission restoration is pending. */
    BOOLEAN Armed;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Preserve the rule identifier that caused the temporary grant. */
    ULONG RuleId;
    /* Preserve the writable target EPT entry. */
    volatile ULONGLONG* Entry;
    /* Preserve the restricted value restored on monitor-trap exit. */
    ULONGLONG RestrictedValue;
    /*
     * Preserve the EPT pointer whose translations this grant invalidated.
     *
     * Zero means the grant was made in the shared hierarchy, which is the
     * feature-off case and the historical behavior.  Carrying it inside the
     * record rather than passing it down keeps every restore caller - the
     * monitor-trap exit, the overlapping-violation path and the VMXOFF
     * cleanup - unchanged.
     */
    ULONGLONG EptPointer;
} KSW_HVM_EPT_TRANSIENT;

/* The violation is unruled or unsafe to continue; leave EPT enforcement. */
#define KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE 0UL
/* One permission was granted for a single instruction; monitor-trap follows. */
#define KSW_HVM_EPT_DISPOSITION_ALLOW_ONCE 1UL
/* The access is denied durably; the dispatcher injects #PF and resumes. */
#define KSW_HVM_EPT_DISPOSITION_INJECT_FAULT 2UL
/*
 * First-touch watch hit: the page's permissions were restored permanently and
 * the hierarchy invalidated.  The dispatcher must resume WITHOUT advancing RIP
 * and WITHOUT arming monitor-trap, so the faulting instruction re-executes and
 * completes normally.
 *
 * This is the only disposition that both records a hit and keeps residency:
 * a strict tripwire records and devirtualizes, allow-once keeps residency but
 * needs monitor-trap to re-restrict, and enforce denies instead of recording.
 * Watch is allow-once minus the re-restrict step, which is exactly why it
 * needs no MTF and therefore works on the nested target.
 */
#define KSW_HVM_EPT_DISPOSITION_WATCH_ONCE 3UL

/*
 * What the watch hit path observed, so the dispatcher can publish evidence
 * without re-deriving any of it in the exit path.
 *
 * Filled only when the disposition is WATCH_ONCE.  FirstHit separates the one
 * processor that won the atomic ARMED -> TRIGGERED transition from the ones
 * that faulted on the same page before the restoration reached them: those
 * must recover silently, never publish a second "first" touch.
 */
typedef struct _KSW_HVM_EPT_WATCH_HIT
{
    /* Set on the single processor that owns this first touch. */
    BOOLEAN FirstHit;
    /* The reported guest-linear address fell inside the requested range. */
    BOOLEAN RangeMatch;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[2];
    /* The watch identifier, equal to the rule identifier. */
    ULONG WatchId;
} KSW_HVM_EPT_WATCH_HIT;

EXTERN_C_START

/*
 * Split one two-MiB identity leaf into 512 four-KiB entries, or return the
 * existing split.  Shared with the EPT view backend, which needs four-KiB
 * granularity for the same reason rules do.
 */
NTSTATUS
KswordARKHvmEptEnsureSplitLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _Outptr_ KSW_HVM_EPT_SPLIT** Split
    );

/* Return the writable four-KiB EPT entry for one already split page. */
volatile ULONGLONG*
KswordARKHvmEptFindLeafEntry(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress
    );


/* Read the actual base leaf, including unsplit MTRR-aware large pages.
 * VM-exit safe while residency freezes the EPT allocation/split ledger. */
BOOLEAN
KswordARKHvmEptReadLeaf(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _Out_ ULONGLONG* Leaf,
    _Out_ ULONG* LeafShift
    );

/* Build a continuous RAM-plus-MMIO identity window under the runtime lock. */
NTSTATUS
KswordARKHvmBuildEptLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Reset EPT rules and restore split leaves before table pages are freed. */
VOID
KswordARKHvmEptResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Execute one versioned EPT rule operation under the runtime lock. */
NTSTATUS
KswordARKHvmEptRuleControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response
    );

/*
 * Handle one EPT violation without allocating or waiting in VMX root.
 * GuestLinearAddressValid tells the aggregation whether a durable denial can
 * be expressed as an injected fault, since that requires a CR2 value.
 */
BOOLEAN
KswordARKHvmEptHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG Access,
    _In_ BOOLEAN GuestLinearAddressValid,
    _In_opt_ const KSW_HVM_EPT_LOCAL* Local,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* RuleId,
    _Out_ ULONG* Disposition,
    _Out_ KSW_HVM_EPT_WATCH_HIT* WatchHit
    );

/*
 * Invalidate every armed watch because residency is ending.
 *
 * A watch is a claim about a window of time in which someone was looking.  Once
 * residency stops, nothing is looking, so an armed watch that survived into the
 * next residency would report "never touched" for a period it did not observe -
 * a fabricated negative result.  The records are kept so the UI can still list
 * them, but only as INVALIDATED, requiring an explicit re-arm.
 */
VOID
KswordARKHvmEptInvalidateWatchesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Restore and invalidate one armed allow-once permission set. */
BOOLEAN
KswordARKHvmEptRestoreTransient(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    );

/* Restore one allow-once permission set on monitor-trap exit. */
BOOLEAN
KswordARKHvmEptHandleMonitorTrap(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    );

/* Execute single-context INVEPT for the current VMX root. */
UCHAR
KswordARKHvmAsmInveptSingle(
    _In_ ULONGLONG EptPointer
    );

EXTERN_C_END
