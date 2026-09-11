/* Portable harness for the two extracted production control lifecycle functions.
 * Shims do not model the Windows I/O manager, IRQL or actual driver unloading.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define _In_
#define _Inout_
#define VOID void
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define NT_ASSERT(x) assert(x)
#define TRUE 1
#define FALSE 0
#define MAXULONG UINT32_MAX
#define IRP_MJ_CREATE 0
#define IRP_MJ_CLOSE 2
#define IRP_MJ_CLEANUP 18
#define FILE_OPENED 1
#define FLTFL_FILTER_UNLOAD_MANDATORY 1
#define STATUS_SUCCESS 0
#define STATUS_DELETE_PENDING (-1)
#define STATUS_INVALID_PARAMETER (-2)
#define STATUS_FLT_DO_NOT_DETACH (-3)
typedef int NTSTATUS;
typedef int BOOLEAN;
typedef uint32_t ULONG;
typedef uintptr_t ULONG_PTR;
typedef unsigned FLT_FILTER_UNLOAD_FLAGS;
typedef void *PDEVICE_OBJECT;
typedef struct { void *FsContext; } FILE_OBJECT;
typedef struct { unsigned MajorFunction; FILE_OBJECT *FileObject; } IO_STACK_LOCATION;
typedef IO_STACK_LOCATION *PIO_STACK_LOCATION;
typedef struct { IO_STACK_LOCATION Stack; NTSTATUS Status; ULONG_PTR Information; } IRP;
typedef IRP *PIRP;
static struct {
    int Lock;
    BOOLEAN Unloading, Active, Initializing, UnloadPrepared;
    ULONG OpenFileObjects;
} g_YcpState;
static int leaseValid, cleanupCalls;
static BOOLEAN initializationValid;
static PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->Stack; }
static void KeEnterCriticalRegion(void) {}
static void KeLeaveCriticalRegion(void) {}
static void ExAcquirePushLockExclusive(int *lock) { assert(!*lock); *lock=1; }
static void ExReleasePushLockExclusive(int *lock) { assert(*lock); *lock=0; }
static NTSTATUS YcpCompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    assert(!g_YcpState.Lock); irp->Status=status; irp->Information=information; return status;
}
static BOOLEAN YcpLeaseValidLocked(void) { assert(g_YcpState.Lock); return leaseValid; }
static BOOLEAN YcpInitializationValidLocked(void) { assert(g_YcpState.Lock); return initializationValid; }
static void YcpCleanup(BOOLEAN unregisterFilter) { assert(!g_YcpState.Lock); (void)unregisterFilter; ++cleanupCalls; }
#include "control_lifecycle_extracted.inc"
static void reset(void) { memset(&g_YcpState,0,sizeof(g_YcpState)); leaseValid=cleanupCalls=initializationValid=0; }
static NTSTATUS dispatch(FILE_OBJECT *file, unsigned major) {
    IRP irp={{major,file},99,99};
    NTSTATUS result=YcpCreateClose(NULL,&irp);
    assert(irp.Status==result);
    assert(irp.Information==((major==IRP_MJ_CREATE && result==0)?FILE_OPENED:0));
    return result;
}
int main(void) {
    FILE_OBJECT a={0}, b={0};
    reset();
    assert(dispatch(&a,IRP_MJ_CREATE)==0);
    assert(dispatch(&b,IRP_MJ_CREATE)==0);
    assert(g_YcpState.OpenFileObjects==2);
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    assert(dispatch(&a,IRP_MJ_CLEANUP)==0);
    assert(g_YcpState.OpenFileObjects==2);
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    assert(dispatch(&a,IRP_MJ_CLOSE)==0);
    assert(g_YcpState.OpenFileObjects==1);
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    assert(dispatch(&b,IRP_MJ_CLOSE)==0);
    assert(YcpFilterUnloadAuthorized(0)==0 && cleanupCalls==1);
    assert(dispatch(&a,IRP_MJ_CREATE)==STATUS_DELETE_PENDING);
    assert(g_YcpState.OpenFileObjects==0);
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    puts("PASS multiple opens, cleanup retains references, final close, unload excludes new opens");

    reset(); g_YcpState.Active=1;
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    leaseValid=1;
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    g_YcpState.UnloadPrepared=1; leaseValid=0;
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    leaseValid=1;
    assert(YcpFilterUnloadAuthorized(0)==0 && cleanupCalls==1);
    puts("PASS active protection requires preparation and a still-valid lease at unload");

    reset(); g_YcpState.Active=1; leaseValid=1; g_YcpState.UnloadPrepared=1;
    assert(dispatch(&a,IRP_MJ_CREATE)==0);
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    assert(dispatch(&a,IRP_MJ_CLOSE)==0);
    leaseValid=0;
    assert(YcpFilterUnloadAuthorized(0)==STATUS_FLT_DO_NOT_DETACH);
    puts("PASS lease expiry while waiting for a connection to close revokes unload");

    reset(); g_YcpState.Initializing=1; initializationValid=0;
    assert(YcpFilterUnloadAuthorized(0)==0 && cleanupCalls==1);
    puts("PASS expired initialization without Active permits recovery unload");

    reset();
    assert(dispatch(NULL,IRP_MJ_CREATE)==STATUS_INVALID_PARAMETER);
    assert(dispatch(&a,IRP_MJ_CLOSE)==0 && g_YcpState.OpenFileObjects==0);
    g_YcpState.OpenFileObjects=MAXULONG;
    assert(dispatch(&a,IRP_MJ_CREATE)==STATUS_INVALID_PARAMETER);
    assert(a.FsContext==NULL && g_YcpState.OpenFileObjects==MAXULONG);
    puts("PASS invalid opens and unmatched closes cannot corrupt the reference count");

    reset(); g_YcpState.Active=1;
    assert(YcpFilterUnloadAuthorized(FLTFL_FILTER_UNLOAD_MANDATORY)==0 && cleanupCalls==1);
    puts("PASS mandatory callback requests cleanup; this is not a veto capability");
    puts("RESULT 6 lifecycle scenarios passed; Windows/WDK, forced-unload races and I/O-manager semantics NOT tested");
    return 0;
}
