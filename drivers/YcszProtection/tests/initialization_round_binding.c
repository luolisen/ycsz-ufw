/* Bind the production snapshot/record functions across an abort and new round. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define VOID void
#define TRUE 1
#define FALSE 0
#define STATUS_PENDING 0x00000103
#define STATUS_SUCCESS 0
#define STATUS_PROCESS_IS_TERMINATING (-1)
#define NT_SUCCESS(status) ((status) >= 0)
#define MAXULONGLONG UINT64_MAX
#define UNREFERENCED_PARAMETER(value) (void)(value)

typedef int NTSTATUS;
typedef int BOOLEAN;
typedef uint32_t ULONG;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef uintptr_t ULONG_PTR;
typedef unsigned char UCHAR;
typedef void *PVOID;
typedef struct _TEST_PROCESS {
    ULONG ProcessId;
    LONGLONG CreateTime100ns;
    BOOLEAN Exited;
    ULONG References;
} TEST_PROCESS, *PEPROCESS;
typedef struct _LARGE_INTEGER {
    LONGLONG QuadPart;
} LARGE_INTEGER;

#include "ycsz_initialization_coverage.h"

typedef struct _YCP_INITIALIZATION_FILE_IDENTITY {
    ULONGLONG VolumeSerialNumber;
    LONGLONG FileIndex;
} YCP_INITIALIZATION_FILE_IDENTITY;

typedef struct _YCP_INITIALIZATION_OBSERVATION_CONTEXT {
    PEPROCESS OwnerProcess;
    ULONGLONG Generation;
    UCHAR InstanceNonce[16];
} YCP_INITIALIZATION_OBSERVATION_CONTEXT, *PYCP_INITIALIZATION_OBSERVATION_CONTEXT;

typedef struct _YCP_TEST_RUNTIME_STATE {
    int Lock;
    PEPROCESS TargetProcess;
    ULONG TargetPid;
    LONGLONG TargetCreateTime100ns;
    BOOLEAN Initializing;
    BOOLEAN Unloading;
    YCP_INITIALIZATION_COVERAGE InitializationCoverage;
    ULONGLONG InitializationGeneration;
    LONGLONG InitializationExpiresAt100ns;
    unsigned char InstanceNonce[16];
} YCP_TEST_RUNTIME_STATE;

static YCP_TEST_RUNTIME_STATE g_YcpState;
static LONGLONG g_Now = 1;

static void RtlZeroMemory(void *memory, size_t size) { memset(memory, 0, size); }
static void RtlCopyMemory(void *destination, const void *source, size_t size) { memcpy(destination, source, size); }
static int RtlEqualMemory(const void *left, const void *right, size_t size) { return memcmp(left, right, size) == 0; }
static void KeEnterCriticalRegion(void) {}
static void KeLeaveCriticalRegion(void) {}
static void ExAcquirePushLockShared(int *lock) { assert(*lock == 0); *lock = 1; }
static void ExReleasePushLockShared(int *lock) { assert(*lock == 1); *lock = 0; }
static void ExAcquirePushLockExclusive(int *lock) { assert(*lock == 0); *lock = 1; }
static void ExReleasePushLockExclusive(int *lock) { assert(*lock == 1); *lock = 0; }
static void ObReferenceObject(PEPROCESS process) { assert(process != NULL); ++process->References; }
static void ObDereferenceObject(PEPROCESS process) { assert(process != NULL && process->References != 0); --process->References; }
static void KeQuerySystemTime(LARGE_INTEGER *now) { now->QuadPart = g_Now; }
static PVOID PsGetProcessId(PEPROCESS process) { return (PVOID)(uintptr_t)process->ProcessId; }
static LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS process) { return process->CreateTime100ns; }
static NTSTATUS PsGetProcessExitStatus(PEPROCESS process) { return process->Exited ? STATUS_PROCESS_IS_TERMINATING : STATUS_PENDING; }

#include "ycsz_initialization_coverage.c"
#include "initialization_round_extracted.inc"

static YCP_INITIALIZATION_COVERAGE_SLOT g_Slots[8];

static void begin_round(PEPROCESS process, ULONGLONG generation, unsigned char marker)
{
    memset(&g_YcpState.InitializationCoverage, 0, sizeof(g_YcpState.InitializationCoverage));
    assert(YcpInitializationCoverageInitialize(&g_YcpState.InitializationCoverage, g_Slots, 8, 2));
    g_YcpState.TargetProcess = process;
    g_YcpState.TargetPid = process->ProcessId;
    g_YcpState.TargetCreateTime100ns = process->CreateTime100ns;
    g_YcpState.Initializing = TRUE;
    g_YcpState.Unloading = FALSE;
    g_YcpState.InitializationGeneration = generation;
    g_YcpState.InitializationExpiresAt100ns = 100;
    memset(g_YcpState.InstanceNonce, marker, sizeof(g_YcpState.InstanceNonce));
    assert(YcpInitializationCoverageDeclare(&g_YcpState.InitializationCoverage, 1, 10, 0));
    assert(YcpInitializationCoverageDeclare(&g_YcpState.InitializationCoverage, 2, 10, 0));
}

int main(void)
{
    TEST_PROCESS owner = { 42, 900, FALSE, 0 };
    TEST_PROCESS other = { 43, 901, FALSE, 0 };
    YCP_INITIALIZATION_OBSERVATION_CONTEXT oldSnapshot;
    YCP_INITIALIZATION_OBSERVATION_CONTEXT currentSnapshot;
    YCP_INITIALIZATION_FILE_IDENTITY first = { 1, 10 };
    YCP_INITIALIZATION_FILE_IDENTITY second = { 2, 10 };

    memset(&g_YcpState, 0, sizeof(g_YcpState));
    begin_round(&owner, 1, 0x11);
    assert(YcpCaptureInitializationSnapshot(&owner, &oldSnapshot));
    assert(owner.References == 1);

    // Abort the old round, then begin a new round for the same process.  The
    // old post-create callback must not alter the new coverage table.
    g_YcpState.Initializing = FALSE;
    begin_round(&owner, 2, 0x22);
    YcpRecordInitializationStream(&oldSnapshot, &first, 0, TRUE);
    assert(g_YcpState.InitializationCoverage.MarkedEntries == 0);
    assert(g_YcpState.InitializationCoverage.Failures == 0);
    YcpReleaseInitializationSnapshot(&oldSnapshot);
    assert(owner.References == 0);

    assert(!YcpCaptureInitializationSnapshot(&other, &currentSnapshot));
    assert(YcpCaptureInitializationSnapshot(&owner, &currentSnapshot));
    YcpRecordInitializationStream(&currentSnapshot, &first, 0, TRUE);
    YcpRecordInitializationStream(&currentSnapshot, &first, 0, TRUE);
    assert(g_YcpState.InitializationCoverage.MarkedEntries == 1);
    assert(g_YcpState.InitializationCoverage.DuplicateEntries == 1);
    YcpRecordInitializationStream(&currentSnapshot, &second, 0, TRUE);
    assert(YcpInitializationCoverageCanCommit(&g_YcpState.InitializationCoverage, 2));
    YcpReleaseInitializationSnapshot(&currentSnapshot);
    assert(owner.References == 0);

    // A completion-context allocation or identity-marking failure records a
    // failure for its captured round, never a successful observation.
    begin_round(&owner, 3, 0x33);
    assert(YcpCaptureInitializationSnapshot(&owner, &currentSnapshot));
    YcpRecordInitializationStream(&currentSnapshot, &first, 0, FALSE);
    assert(g_YcpState.InitializationCoverage.MarkedEntries == 0);
    assert(g_YcpState.InitializationCoverage.Failures == 1);
    assert(!YcpInitializationCoverageCanCommit(&g_YcpState.InitializationCoverage, 2));
    YcpReleaseInitializationSnapshot(&currentSnapshot);
    assert(owner.References == 0);

    puts("PASS production initialization snapshot binding: old-round rejection, same-round dedupe, owner isolation, failure and reference cleanup");
    return 0;
}
