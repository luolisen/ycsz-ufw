/* Exercise the production per-identity coverage implementation directly. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "ycsz_initialization_coverage.c"

static void initialize(
    YCP_INITIALIZATION_COVERAGE *coverage,
    YCP_INITIALIZATION_COVERAGE_SLOT *slots,
    uint32_t maximum
    )
{
    assert(YcpInitializationCoverageInitialize(coverage, slots, 8, maximum));
}

int main(void)
{
    YCP_INITIALIZATION_COVERAGE coverage;
    YCP_INITIALIZATION_COVERAGE_SLOT slots[8];

    initialize(&coverage, slots, 2);
    assert(YcpInitializationCoverageDeclare(&coverage, 1, 10, 0));
    assert(YcpInitializationCoverageDeclare(&coverage, 2, 10, 0));
    assert(YcpInitializationCoverageObserve(&coverage, 1, 10, 0, 1));
    assert(YcpInitializationCoverageObserve(&coverage, 1, 10, 0, 1));
    assert(coverage.MarkedEntries == 1 && coverage.DuplicateEntries == 1);
    assert(!YcpInitializationCoverageCanCommit(&coverage, 2));
    assert(YcpInitializationCoverageObserve(&coverage, 2, 10, 0, 1));
    assert(YcpInitializationCoverageCanCommit(&coverage, 2));

    initialize(&coverage, slots, 1);
    assert(!YcpInitializationCoverageObserve(&coverage, 1, 10, 0, 1));
    assert(coverage.UnexpectedEntries == 1 && coverage.Failures == 1);
    assert(YcpInitializationCoverageDeclare(&coverage, 2, 10, 0));
    assert(YcpInitializationCoverageObserve(&coverage, 2, 10, 0, 1));
    assert(!YcpInitializationCoverageCanCommit(&coverage, 1));

    initialize(&coverage, slots, 2);
    assert(YcpInitializationCoverageDeclare(&coverage, 1, 7, 0));
    assert(YcpInitializationCoverageDeclare(&coverage, 2, 7, 0));
    assert(YcpInitializationCoverageObserve(&coverage, 1, 7, 0, 1));
    assert(YcpInitializationCoverageObserve(&coverage, 2, 7, 0, 1));
    assert(YcpInitializationCoverageCanCommit(&coverage, 2));

    initialize(&coverage, slots, 1);
    assert(!YcpInitializationCoverageDeclare(&coverage, 0, 0, 0));
    assert(!YcpInitializationCoverageDeclare(&coverage, 3, 3, 1));
    assert(YcpInitializationCoverageDeclare(&coverage, 3, 3, 0));
    assert(!YcpInitializationCoverageObserve(&coverage, 3, 3, 1, 1));
    assert(!YcpInitializationCoverageObserve(&coverage, 3, 3, 0, 0));
    assert(!YcpInitializationCoverageCanCommit(&coverage, 1));

    puts("PASS production initialization coverage: distinct identities, duplicate/missing, old-round, multi-volume and failure-capacity cases");
    return 0;
}
