#pragma once

#include <stdint.h>

typedef struct _YCP_INITIALIZATION_COVERAGE_SLOT {
    uint64_t VolumeSerialNumber;
    int64_t FileIndex;
    uint32_t Flags;
    uint32_t State;
} YCP_INITIALIZATION_COVERAGE_SLOT, *PYCP_INITIALIZATION_COVERAGE_SLOT;

typedef struct _YCP_INITIALIZATION_COVERAGE {
    PYCP_INITIALIZATION_COVERAGE_SLOT Slots;
    uint32_t SlotCount;
    uint32_t MaximumEntries;
    uint32_t DeclaredEntries;
    uint32_t MarkedEntries;
    uint32_t Failures;
    uint32_t UnexpectedEntries;
    uint32_t DuplicateEntries;
} YCP_INITIALIZATION_COVERAGE, *PYCP_INITIALIZATION_COVERAGE;

#define YCP_COVERAGE_SLOT_EMPTY       0u
#define YCP_COVERAGE_SLOT_DECLARED    1u
#define YCP_COVERAGE_SLOT_OBSERVED    2u

int
YcpInitializationCoverageInitialize(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    PYCP_INITIALIZATION_COVERAGE_SLOT Slots,
    uint32_t SlotCount,
    uint32_t MaximumEntries
    );

int
YcpInitializationCoverageDeclare(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    uint64_t VolumeSerialNumber,
    int64_t FileIndex,
    uint32_t Flags
    );

int
YcpInitializationCoverageObserve(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    uint64_t VolumeSerialNumber,
    int64_t FileIndex,
    uint32_t Flags,
    int Marked
    );

int
YcpInitializationCoverageCanCommit(
    const YCP_INITIALIZATION_COVERAGE *Coverage,
    uint32_t ExpectedEntries
    );
