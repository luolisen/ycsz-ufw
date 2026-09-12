#include "ycsz_initialization_coverage.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

static void
YcpCoverageIncrement(
    YCP_UINT32 *Value
    )
{
    if (*Value != YCP_UINT32_MAX) {
        ++*Value;
    }
}

static YCP_UINT32
YcpCoverageHash(
    YCP_UINT64 VolumeSerialNumber,
    YCP_INT64 FileIndex
    )
{
    YCP_UINT64 value = VolumeSerialNumber ^ (YCP_UINT64)FileIndex;
    value ^= value >> 33;
    value *= YCP_UINT64_C(0xff51afd7ed558ccd);
    value ^= value >> 33;
    value *= YCP_UINT64_C(0xc4ceb9fe1a85ec53);
    value ^= value >> 33;
    return (YCP_UINT32)(value ^ (value >> 32));
}

static PYCP_INITIALIZATION_COVERAGE_SLOT
YcpCoverageFind(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    YCP_UINT64 VolumeSerialNumber,
    YCP_INT64 FileIndex,
    int *Found
    )
{
    YCP_UINT32 index;
    YCP_UINT32 probe;

    *Found = 0;
    if (Coverage == NULL || Coverage->Slots == NULL || Coverage->SlotCount == 0 ||
        (Coverage->SlotCount & (Coverage->SlotCount - 1u)) != 0) {
        return NULL;
    }

    index = YcpCoverageHash(VolumeSerialNumber, FileIndex) & (Coverage->SlotCount - 1u);
    for (probe = 0; probe < Coverage->SlotCount; ++probe) {
        PYCP_INITIALIZATION_COVERAGE_SLOT slot = &Coverage->Slots[index];
        if (slot->State == YCP_COVERAGE_SLOT_EMPTY) {
            return slot;
        }
        if (slot->VolumeSerialNumber == VolumeSerialNumber &&
            slot->FileIndex == FileIndex) {
            *Found = 1;
            return slot;
        }
        index = (index + 1u) & (Coverage->SlotCount - 1u);
    }
    return NULL;
}

int
YcpInitializationCoverageInitialize(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    PYCP_INITIALIZATION_COVERAGE_SLOT Slots,
    YCP_UINT32 SlotCount,
    YCP_UINT32 MaximumEntries
    )
{
    YCP_UINT32 index;

    if (Coverage == NULL || Slots == NULL || SlotCount < 2u ||
        (SlotCount & (SlotCount - 1u)) != 0 || MaximumEntries == 0 ||
        MaximumEntries > SlotCount / 2u) {
        return 0;
    }
    for (index = 0; index < SlotCount; ++index) {
        Slots[index].VolumeSerialNumber = 0;
        Slots[index].FileIndex = 0;
        Slots[index].Flags = 0;
        Slots[index].State = YCP_COVERAGE_SLOT_EMPTY;
    }
    Coverage->Slots = Slots;
    Coverage->SlotCount = SlotCount;
    Coverage->MaximumEntries = MaximumEntries;
    Coverage->DeclaredEntries = 0;
    Coverage->MarkedEntries = 0;
    Coverage->Failures = 0;
    Coverage->UnexpectedEntries = 0;
    Coverage->DuplicateEntries = 0;
    return 1;
}

int
YcpInitializationCoverageDeclare(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    YCP_UINT64 VolumeSerialNumber,
    YCP_INT64 FileIndex,
    YCP_UINT32 Flags
    )
{
    int found;
    PYCP_INITIALIZATION_COVERAGE_SLOT slot;

    if (Coverage == NULL || (VolumeSerialNumber == 0 && FileIndex == 0) || Flags != 0 ||
        Coverage->DeclaredEntries >= Coverage->MaximumEntries) {
        if (Coverage != NULL) YcpCoverageIncrement(&Coverage->Failures);
        return 0;
    }
    slot = YcpCoverageFind(Coverage, VolumeSerialNumber, FileIndex, &found);
    if (slot == NULL || found) {
        YcpCoverageIncrement(&Coverage->Failures);
        if (found) YcpCoverageIncrement(&Coverage->DuplicateEntries);
        return 0;
    }
    slot->VolumeSerialNumber = VolumeSerialNumber;
    slot->FileIndex = FileIndex;
    slot->Flags = Flags;
    slot->State = YCP_COVERAGE_SLOT_DECLARED;
    ++Coverage->DeclaredEntries;
    return 1;
}

int
YcpInitializationCoverageObserve(
    PYCP_INITIALIZATION_COVERAGE Coverage,
    YCP_UINT64 VolumeSerialNumber,
    YCP_INT64 FileIndex,
    YCP_UINT32 Flags,
    int Marked
    )
{
    int found;
    PYCP_INITIALIZATION_COVERAGE_SLOT slot;

    if (Coverage == NULL || !Marked || (VolumeSerialNumber == 0 && FileIndex == 0)) {
        if (Coverage != NULL) YcpCoverageIncrement(&Coverage->Failures);
        return 0;
    }
    slot = YcpCoverageFind(Coverage, VolumeSerialNumber, FileIndex, &found);
    if (slot == NULL || !found) {
        YcpCoverageIncrement(&Coverage->Failures);
        YcpCoverageIncrement(&Coverage->UnexpectedEntries);
        return 0;
    }
    if (slot->Flags != Flags) {
        YcpCoverageIncrement(&Coverage->Failures);
        return 0;
    }
    if (slot->State == YCP_COVERAGE_SLOT_OBSERVED) {
        YcpCoverageIncrement(&Coverage->DuplicateEntries);
        return 1;
    }
    if (slot->State != YCP_COVERAGE_SLOT_DECLARED) {
        YcpCoverageIncrement(&Coverage->Failures);
        return 0;
    }
    slot->State = YCP_COVERAGE_SLOT_OBSERVED;
    ++Coverage->MarkedEntries;
    return 1;
}

int
YcpInitializationCoverageCanCommit(
    const YCP_INITIALIZATION_COVERAGE *Coverage,
    YCP_UINT32 ExpectedEntries
    )
{
    return Coverage != NULL && ExpectedEntries != 0 &&
        ExpectedEntries == Coverage->MaximumEntries &&
        Coverage->DeclaredEntries == ExpectedEntries &&
        Coverage->MarkedEntries == ExpectedEntries &&
        Coverage->Failures == 0 && Coverage->UnexpectedEntries == 0;
}
