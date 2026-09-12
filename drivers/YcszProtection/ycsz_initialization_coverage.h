#pragma once

#if defined(_KERNEL_MODE)
#include <ntifs.h>
typedef ULONG YCP_UINT32;
typedef ULONGLONG YCP_UINT64;
typedef LONGLONG YCP_INT64;
#define YCP_UINT32_MAX ((YCP_UINT32)0xffffffffUL)
#define YCP_UINT64_C(value) value##ULL
#else
#include <stdint.h>
typedef uint32_t YCP_UINT32;
typedef uint64_t YCP_UINT64;
typedef int64_t YCP_INT64;
#define YCP_UINT32_MAX UINT32_MAX
#define YCP_UINT64_C(value) UINT64_C(value)
#endif

typedef struct _YCP_INITIALIZATION_COVERAGE_SLOT {
    YCP_UINT64 VolumeSerialNumber;
    YCP_INT64 FileIndex;
    YCP_UINT32 Flags;
    YCP_UINT32 State;
} YCP_INITIALIZATION_COVERAGE_SLOT, *PYCP_INITIALIZATION_COVERAGE_SLOT;

typedef struct _YCP_INITIALIZATION_COVERAGE {
    PYCP_INITIALIZATION_COVERAGE_SLOT Slots;
    YCP_UINT32 SlotCount;
    YCP_UINT32 MaximumEntries;
    YCP_UINT32 DeclaredEntries;
    YCP_UINT32 MarkedEntries;
    YCP_UINT32 Failures;
    YCP_UINT32 UnexpectedEntries;
    YCP_UINT32 DuplicateEntries;
} YCP_INITIALIZATION_COVERAGE, *PYCP_INITIALIZATION_COVERAGE;

#define YCP_COVERAGE_SLOT_EMPTY       0u
#define YCP_COVERAGE_SLOT_DECLARED    1u
#define YCP_COVERAGE_SLOT_OBSERVED    2u

int
YcpInitializationCoverageInitialize(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    PYCP_INITIALIZATION_COVERAGE_SLOT Slots,
    YCP_UINT32 SlotCount,
    YCP_UINT32 MaximumEntries
    );

int
YcpInitializationCoverageDeclare(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    YCP_UINT64 VolumeSerialNumber,
    YCP_INT64 FileIndex,
    YCP_UINT32 Flags
    );

int
YcpInitializationCoverageObserve(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    YCP_UINT64 VolumeSerialNumber,
    YCP_INT64 FileIndex,
    YCP_UINT32 Flags,
    int Marked
    );

int
YcpInitializationCoverageCanCommit(
    const YCP_INITIALIZATION_COVERAGE *Coverage,
    YCP_UINT32 ExpectedEntries
    );
