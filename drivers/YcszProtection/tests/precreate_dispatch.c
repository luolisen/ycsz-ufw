/* Real pre-operation function with portable API stubs; not a Windows kernel test. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define _Inout_
#define _In_
#define _Flt_CompletionContext_Outptr_
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(x) ((x)>=0)
#define IRP_MJ_CREATE 0
#define IRP_MJ_WRITE 4
#define IRP_MJ_SET_INFORMATION 6
#define IRP_MJ_FILE_SYSTEM_CONTROL 9
#define IRP_PAGING_IO 2
#define FLT_FILE_NAME_NORMALIZED 1
#define FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP 2
#define FLT_PREOP_SUCCESS_NO_CALLBACK 0
#define FLT_PREOP_SUCCESS_WITH_CALLBACK 1
#define FLT_PREOP_COMPLETE 2
#define FileRenameInformation 1
#define FileRenameInformationEx 2
#define FileLinkInformation 3
#define FileLinkInformationEx 4
#define FILE_DELETE_ON_CLOSE 0x1000
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE_IF 5
#define FILE_SUPERSEDE 0
typedef unsigned long ULONG;
typedef unsigned long long ULONGLONG;
typedef unsigned char UCHAR;
typedef void *PEPROCESS;
typedef int BOOLEAN;
typedef int NTSTATUS;
typedef int FLT_PREOP_CALLBACK_STATUS;
typedef void *PVOID;
typedef struct _YCP_INITIALIZATION_OBSERVATION_CONTEXT {
    PEPROCESS OwnerProcess;
    ULONGLONG Generation;
    UCHAR InstanceNonce[16];
} YCP_INITIALIZATION_OBSERVATION_CONTEXT, *PYCP_INITIALIZATION_OBSERVATION_CONTEXT;
typedef struct { int Name; } NAME;
typedef NAME *PFLT_FILE_NAME_INFORMATION;
typedef struct { int MajorFunction,IrpFlags; struct { struct { ULONG Options; } Create; struct { int FileInformationClass; } SetFileInformation; } Parameters; } IOPB;
typedef struct { IOPB *Iopb; } DATA;
typedef DATA *PFLT_CALLBACK_DATA;
typedef void *PCFLT_RELATED_OBJECTS;
static int active=1, initializing, mutation, trusted, product, stream, resolved=1, ancestor;
static int streamQueries;
static void *FltGetRequestorProcess(DATA *d) { (void)d; return NULL; }
static int YcpCaptureInitializationSnapshot(PEPROCESS requestor, PYCP_INITIALIZATION_OBSERVATION_CONTEXT snapshot) { (void)requestor; (void)snapshot; return 0; }
static void YcpReleaseInitializationSnapshot(PYCP_INITIALIZATION_OBSERVATION_CONTEXT snapshot) { (void)snapshot; }
static void YcpRecordInitializationStream(const YCP_INITIALIZATION_OBSERVATION_CONTEXT *snapshot, void *identity, ULONG flags, BOOLEAN marked) { (void)snapshot; (void)identity; (void)flags; (void)marked; }
static void *ExAllocatePool2(unsigned long flags, size_t size, unsigned long tag) { (void)flags; (void)tag; return calloc(1, size); }
#define POOL_FLAG_NON_PAGED 1UL
#define YCP_POOL_TAG 0x59435059UL
static void RtlZeroMemory(void *memory, size_t size) { memset(memory, 0, size); }
static int YcpCreateChangesNamespace(PFLT_CALLBACK_DATA Data);
static NAME name;
static int YcpProtectionIsActive(void) { return active; }
static int YcpProtectionIsInitializing(void) { return initializing; }
static int YcpCreateRequestsMutation(DATA *d) { (void)d; return mutation; }
static int YcpIsProtectedSetInformationClass(int c) { (void)c; return mutation; }
static int YcpFileSystemControlRequestsMutation(DATA *d) { (void)d; return mutation; }
static int YcpStreamIsProtected(void *o) { (void)o; ++streamQueries; return stream; }
static int FltGetFileNameInformation(DATA *d,int flags,NAME **out) { (void)d;(void)flags;*out=resolved?&name:NULL; return resolved?0:-1; }
static int FltParseFileNameInformation(NAME *n) { (void)n; return 0; }
static int YcpShouldProtectAncestor(int *n) { (void)n; return ancestor; }
static int YcpShouldProtectFile(int *n) { (void)n; return product; }
static int YcpDestinationIsProtected(DATA *d,void *o,int *r) { (void)d;(void)o;*r=1;return 0; }
static int YcpIsTrustedWriter(DATA *d) { (void)d; return trusted; }
static int YcpIsNamespaceMutation(DATA *d) { return d->Iopb->MajorFunction==IRP_MJ_SET_INFORMATION || YcpCreateChangesNamespace(d); }
static int YcpDenyMutation(DATA *d) { (void)d;return FLT_PREOP_COMPLETE; }
#include "precreate_extracted.inc"
int main(void) {
    IOPB op={0}; DATA data={&op}; void *completion=(void *)1;
    op.Parameters.Create.Options=1UL<<24; /* FILE_OPEN */
    op.MajorFunction=IRP_MJ_CREATE; product=1;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK && completion==NULL);
    mutation=1; trusted=1;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
    assert(streamQueries==0); /* No stream-context API in pre-create. */
    trusted=0;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_COMPLETE);
    product=0;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
    resolved=0;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
    op.MajorFunction=IRP_MJ_WRITE; product=1; resolved=1; op.IrpFlags=IRP_PAGING_IO;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_NO_CALLBACK);
    active=0; op.MajorFunction=IRP_MJ_CREATE;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_NO_CALLBACK);
    active=1; ancestor=1; product=0; trusted=1; op.IrpFlags=0;
    op.MajorFunction=IRP_MJ_SET_INFORMATION; op.Parameters.SetFileInformation.FileInformationClass=FileRenameInformation;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_COMPLETE);
    op.MajorFunction=IRP_MJ_WRITE;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_NO_CALLBACK);
    active=0; initializing=1; ancestor=0; product=1; mutation=0;
    op.MajorFunction=IRP_MJ_CREATE;
    op.Parameters.Create.Options=(ULONG)FILE_CREATE<<24;
    /* Creating with no write access still changes the scanned namespace. */
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_COMPLETE);
    op.Parameters.Create.Options=(ULONG)FILE_OPEN_IF<<24;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_COMPLETE);
    product=0;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
    product=1; op.Parameters.Create.Options=1UL<<24;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
    active=1; initializing=0; trusted=1;
    op.Parameters.Create.Options=(ULONG)FILE_CREATE<<24;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
    trusted=0;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_COMPLETE);
    trusted=1; product=0; ancestor=1;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_COMPLETE);
    puts("PASS 16 pre-operation dispatch scenarios; trusted active creates allowed, initializing and untrusted creates guarded, ancestor restrictions preserved");
    return 0;
}
