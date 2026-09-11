/* Real pre-operation function with portable API stubs; not a Windows kernel test. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
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
typedef int BOOLEAN;
typedef int NTSTATUS;
typedef int FLT_PREOP_CALLBACK_STATUS;
typedef void *PVOID;
typedef struct { int Name; } NAME;
typedef NAME *PFLT_FILE_NAME_INFORMATION;
typedef struct { int MajorFunction,IrpFlags; struct { struct { int FileInformationClass; } SetFileInformation; } Parameters; } IOPB;
typedef struct { IOPB *Iopb; } DATA;
typedef DATA *PFLT_CALLBACK_DATA;
typedef void *PCFLT_RELATED_OBJECTS;
static int active=1, mutation, trusted, product, stream, resolved=1, ancestor;
static NAME name;
static int YcpProtectionIsActive(void) { return active; }
static int YcpCreateRequestsMutation(DATA *d) { (void)d; return mutation; }
static int YcpIsProtectedSetInformationClass(int c) { (void)c; return mutation; }
static int YcpFileSystemControlRequestsMutation(DATA *d) { (void)d; return mutation; }
static int YcpStreamIsProtected(void *o) { (void)o; return stream; }
static int FltGetFileNameInformation(DATA *d,int flags,NAME **out) { (void)d;(void)flags;*out=resolved?&name:NULL; return resolved?0:-1; }
static int FltParseFileNameInformation(NAME *n) { (void)n; return 0; }
static int YcpShouldProtectAncestor(int *n) { (void)n; return ancestor; }
static int YcpShouldProtectFile(int *n) { (void)n; return product; }
static int YcpDestinationIsProtected(DATA *d,void *o,int *r) { (void)d;(void)o;*r=1;return 0; }
static void FltReleaseFileNameInformation(NAME *n) { (void)n; }
static int YcpIsTrustedWriter(DATA *d) { (void)d; return trusted; }
static int YcpIsNamespaceMutation(DATA *d) { return d->Iopb->MajorFunction==IRP_MJ_SET_INFORMATION; }
static int YcpTrustedNamespaceMutationAllowed(DATA *d,int s,int t,int r) { (void)d;(void)s;(void)t;(void)r;return 0; }
static int YcpDenyMutation(DATA *d) { (void)d;return FLT_PREOP_COMPLETE; }
#include "precreate_extracted.inc"
int main(void) {
    IOPB op={0}; DATA data={&op}; void *completion=(void *)1;
    op.MajorFunction=IRP_MJ_CREATE; product=1;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK && completion==NULL);
    mutation=1; trusted=1;
    assert(YcpPreOperationFile(&data,NULL,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
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
    puts("PASS 9 pre-operation dispatch scenarios; allowed creates request post callbacks, denied creates do not, unrelated/paging I/O preserved");
    return 0;
}
