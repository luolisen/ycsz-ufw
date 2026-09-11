/* Portable harness for the extracted stream-context attachment helper.
 * It checks Filter Manager reference balancing separately from context
 * references; it does not model Windows I/O manager, IRQL or real streams.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _In_
#define _Out_
#define _In_opt_
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_SUCCESS 0
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED 1
#define STATUS_FLT_CONTEXT_ALLOCATION_FAILED (-10)
#define STATUS_FLT_CONTEXT_SET_FAILED (-11)
#define FLT_STREAM_CONTEXT 1
#define FLT_SET_CONTEXT_KEEP_IF_EXISTS 1
#define NonPagedPoolNx 0
#define YCP_POOL_TAG 0x59435059u
#define UNREFERENCED_PARAMETER(value) (void)(value)

typedef int NTSTATUS;
typedef int BOOLEAN;
typedef uint32_t ULONG;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef LARGE_INTEGER *PLARGE_INTEGER;
typedef struct _FILE_OBJECT { int unused; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct _FLT_INSTANCE { int unused; } FLT_INSTANCE, *PFLT_INSTANCE;
typedef struct _FLT_FILTER { int unused; } FLT_FILTER, *PFLT_FILTER;
typedef struct _FLT_RELATED_OBJECTS {
    PFLT_INSTANCE Instance;
    PFLT_FILTER Filter;
    PFILE_OBJECT FileObject;
} FLT_RELATED_OBJECTS, *PCFLT_RELATED_OBJECTS;

typedef struct _YCP_STREAM_CONTEXT {
    ULONG Version;
    BOOLEAN ProductStream;
    LARGE_INTEGER FileId;
} YCP_STREAM_CONTEXT, *PYCP_STREAM_CONTEXT;

typedef struct _TEST_CONTEXT {
    YCP_STREAM_CONTEXT Public;
    int References;
} TEST_CONTEXT;
typedef TEST_CONTEXT *PFLT_CONTEXT;

static int getCalls;
static int getFailures;
static int filterReferences;
static int filterDereferences;
static int allocationCalls;
static int allocationFailures;
static int setCalls;
static int setFailures;
static int contextReleases;
static PFLT_CONTEXT existingContext;
static FLT_FILTER filterObject;

static NTSTATUS FltGetFilterFromInstance(PFLT_INSTANCE instance, PFLT_FILTER *filter) {
    UNREFERENCED_PARAMETER(instance);
    ++getCalls;
    if (getFailures) return -20;
    *filter = &filterObject;
    ++filterReferences;
    return STATUS_SUCCESS;
}

static NTSTATUS FltAllocateContext(PFLT_FILTER filter, int type, size_t size, int pool, PFLT_CONTEXT *context) {
    TEST_CONTEXT *allocated;
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(pool);
    ++allocationCalls;
    assert(size == sizeof(YCP_STREAM_CONTEXT));
    if (allocationFailures) return STATUS_FLT_CONTEXT_ALLOCATION_FAILED;
    allocated = (TEST_CONTEXT *)calloc(1, sizeof(*allocated));
    assert(allocated != NULL);
    allocated->References = 1;
    *context = allocated;
    return STATUS_SUCCESS;
}

static void FltObjectDereference(PFLT_FILTER filter) {
    assert(filter == &filterObject);
    assert(filterReferences > 0);
    --filterReferences;
    ++filterDereferences;
}

static NTSTATUS FltSetStreamContext(PFLT_INSTANCE instance, PFILE_OBJECT file, int mode, PFLT_CONTEXT context, PFLT_CONTEXT *old) {
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(file);
    assert(mode == FLT_SET_CONTEXT_KEEP_IF_EXISTS);
    ++setCalls;
    *old = NULL;
    if (setFailures) return STATUS_FLT_CONTEXT_SET_FAILED;
    if (existingContext != NULL) {
        ++existingContext->References;
        *old = existingContext;
        return STATUS_FLT_CONTEXT_ALREADY_DEFINED;
    }
    existingContext = context;
    ++context->References;
    return STATUS_SUCCESS;
}

static void FltReleaseContext(PFLT_CONTEXT context) {
    assert(context != NULL);
    assert(context->References > 0);
    --context->References;
    ++contextReleases;
    if (context->References == 0) free(context);
}

#include "stream_context_extracted.inc"

static void reset(void) {
    if (existingContext != NULL) {
        FltReleaseContext(existingContext);
        existingContext = NULL;
    }
    getCalls = getFailures = filterReferences = filterDereferences = 0;
    allocationCalls = allocationFailures = setCalls = setFailures = contextReleases = 0;
}

static FLT_RELATED_OBJECTS objects(void) {
    static FLT_INSTANCE instance;
    static FILE_OBJECT file;
    FLT_RELATED_OBJECTS result = { &instance, &filterObject, &file };
    return result;
}

static void assert_filter_balanced(void) {
    assert(filterReferences == 0);
    assert(filterDereferences == getCalls - getFailures);
}

int main(void) {
    FLT_RELATED_OBJECTS related = objects();
    LARGE_INTEGER fileId = { 77 };
    TEST_CONTEXT seeded = { { 1, TRUE, { 88 } }, 1 };
    BOOLEAN attached;

    reset();
    getFailures = 1;
    attached = YcpAttachProtectedStreamContext(&related, &fileId);
    assert(!attached && getCalls == 1 && allocationCalls == 0 && setCalls == 0);
    assert_filter_balanced();

    reset();
    allocationFailures = 1;
    attached = YcpAttachProtectedStreamContext(&related, &fileId);
    assert(!attached && allocationCalls == 1 && setCalls == 0 && contextReleases == 0);
    assert_filter_balanced();

    reset();
    setFailures = 1;
    attached = YcpAttachProtectedStreamContext(&related, &fileId);
    assert(!attached && setCalls == 1 && contextReleases == 1);
    assert_filter_balanced();

    reset();
    existingContext = &seeded;
    attached = YcpAttachProtectedStreamContext(&related, &fileId);
    assert(attached && setCalls == 1 && contextReleases == 2 && existingContext == &seeded);
    assert_filter_balanced();
    existingContext = NULL;
    assert(seeded.References == 1);

    reset();
    attached = YcpAttachProtectedStreamContext(&related, &fileId);
    assert(attached && setCalls == 1 && contextReleases == 1 && existingContext != NULL);
    assert_filter_balanced();
    FltReleaseContext(existingContext);
    existingContext = NULL;
    puts("PASS filter reference and stream-context references balance on get, allocate, set and existing-context paths");
    return 0;
}
