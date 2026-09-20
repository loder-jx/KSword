#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KSW_HVM_COMMAND_MAX_ARGS 4

typedef enum HVM_COMMAND_HANDLER {
    HvmControl, HvmStatus, HvmCpuid, HvmPlatform, HvmFlags, HvmAcl,
    HvmNestedProbe, HvmNestedProbeAll, HvmNestedAd, HvmSelfvirt, HvmSelfvirtAll,
    HvmGdt, HvmMsrLog, HvmMsrClear, HvmXonly, HvmAllowOnce, HvmTlb, HvmTlbExit,
    HvmViewQuery, HvmViewProbe, HvmViewEffect, HvmSelfcheck, HvmViewVerify,
    HvmEptLeaf, HvmEvents, HvmCrOn, HvmCrOff,
    HvmInjectQuery, HvmInjectTest, HvmInjectDll, HvmInjectRelease, HvmInjectClear,
    HvmProcQuery, HvmProcFreeze, HvmProcTerminate, HvmProcRelease, HvmProcClear,
    HvmPageQuery, HvmPageMap, HvmPageRemove, HvmMetrics, HvmPageMapTest, HvmPageRemoveTest,
    /* Region overrides: publish at a chosen leaf granularity, then edit one page
       of the published region at a time. Appended rather than inserted so every
       existing handler keeps its ordinal. */
    HvmPageMapRegion, HvmPageMapRegionScan, HvmPageStage, HvmPageDigest,
    /* First-touch memory watch.  Appended so every existing ordinal is kept. */
    HvmWatchAddVa, HvmWatchAddPa, HvmWatchList, HvmWatchRearm, HvmWatchRemove,
    HvmWatchSelfTest, HvmWatchSelfTestRead, HvmWatchSelfTestExec,
    HvmWatchSelfTestSmp, HvmWatchSelfTestRemap, HvmWatchSelfTestEvidence,
    HvmWatchSelfTestConflict, HvmWatchSelfTestRestart, HvmWatchSelfTestProcess,
    HvmHelp, HvmCommands
} HVM_COMMAND_HANDLER;

typedef enum HVM_ARGUMENT_KIND {
    HvmDecimal32, HvmDecimal64, HvmHex32, HvmHex64, HvmPageAddress, HvmByte, HvmPath
} HVM_ARGUMENT_KIND;

typedef struct HVM_COMMAND_ARGUMENT {
    const char* name;
    HVM_ARGUMENT_KIND kind;
    const char* defaultValue; /* NULL means required. Values retain their declared base. */
} HVM_COMMAND_ARGUMENT;

typedef struct HVM_COMMAND_SPEC {
    const char* name;
    const char* title;
    const char* group;
    const char* description;
    HVM_COMMAND_HANDLER handler;
    int readOnly;
    unsigned long command;
    unsigned long flags;
    unsigned int argumentCount;
    HVM_COMMAND_ARGUMENT arguments[KSW_HVM_COMMAND_MAX_ARGS];
} HVM_COMMAND_SPEC;

const HVM_COMMAND_SPEC* KswordHvmCommands(size_t* count);
const HVM_COMMAND_SPEC* KswordHvmFindCommand(const char* name);
/* Returns 0 on success. No driver access; used by both the form and dispatcher. */
int KswordHvmValidateArguments(const HVM_COMMAND_SPEC* command, int count,
    const char* const* arguments, unsigned long long values[KSW_HVM_COMMAND_MAX_ARGS],
    char* error, size_t errorSize);
void KswordHvmPrintCommands(int asJson);
void KswordHvmPrintJsonString(const char* text);
int KswordHvmCommandMain(int argc, char** argv);
int KswordHvmCommandMainWide(int argc, wchar_t** argv);

#ifdef __cplusplus
}
#endif
