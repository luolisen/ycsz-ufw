#include "ycsz_protection.h"

typedef struct _YCP_STREAM_CONTEXT {
    ULONG Version;
    BOOLEAN ProductStream;
    LARGE_INTEGER FileId;
} YCP_STREAM_CONTEXT, *PYCP_STREAM_CONTEXT;

static BOOLEAN
YcpFileSystemControlRequestsMutation(
    _In_ PFLT_CALLBACK_DATA Data
    );

static VOID
YcpStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

static const FLT_CONTEXT_REGISTRATION g_YcpContextRegistration[] = {
    { FLT_STREAM_CONTEXT, 0, YcpStreamContextCleanup, sizeof(YCP_STREAM_CONTEXT), YCP_POOL_TAG },
    { FLT_CONTEXT_END }
};

static BOOLEAN
YcpStreamIsProtected(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PFLT_CONTEXT context = NULL;
    NTSTATUS status;
    BOOLEAN protected = FALSE;

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return FALSE;
    }
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, &context);
    if (NT_SUCCESS(status) && context != NULL) {
        protected = ((PYCP_STREAM_CONTEXT)context)->ProductStream ? TRUE : FALSE;
        FltReleaseContext(context);
    }
    return protected;
}

static BOOLEAN
YcpMarkProtectedStream(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    FILE_INTERNAL_INFORMATION fileInformation;
    PFLT_CONTEXT context = NULL;
    PFLT_CONTEXT oldContext = NULL;
    PFLT_FILTER filter;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return FALSE;
    }
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &fileInformation,
        sizeof(fileInformation),
        FileInternalInformation,
        NULL);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    status = FltGetFilterFromInstance(FltObjects->Instance, &filter);
    if (!NT_SUCCESS(status) || filter == NULL) {
        return FALSE;
    }
    status = FltAllocateContext(
        filter,
        FLT_STREAM_CONTEXT,
        sizeof(YCP_STREAM_CONTEXT),
        NonPagedPoolNx,
        &context);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    ((PYCP_STREAM_CONTEXT)context)->Version = 1;
    ((PYCP_STREAM_CONTEXT)context)->ProductStream = TRUE;
    ((PYCP_STREAM_CONTEXT)context)->FileId = fileInformation.IndexNumber;
    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        context,
        &oldContext);
    FltReleaseContext(context);
    if (oldContext != NULL) {
        FltReleaseContext(oldContext);
    }
    return NT_SUCCESS(status) || status == STATUS_FLT_CONTEXT_ALREADY_DEFINED;
}

static BOOLEAN
YcpIsNamespaceMutation(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    FILE_INFORMATION_CLASS informationClass;

    if (Data == NULL || Data->Iopb == NULL) {
        return FALSE;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
        return YcpFileSystemControlRequestsMutation(Data);
    }
    if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION) {
        return FALSE;
    }
    informationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    return informationClass == FileRenameInformation ||
        informationClass == FileRenameInformationEx ||
        informationClass == FileLinkInformation ||
        informationClass == FileLinkInformationEx;
}

static BOOLEAN
YcpCreateRequestsMutation(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ULONG options;
    ACCESS_MASK desiredAccess;
    ULONG disposition;

    options = Data->Iopb->Parameters.Create.Options;
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext != NULL
        ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
        : 0;
    disposition = (options >> 24) & 0xff;

    if ((options & FILE_DELETE_ON_CLOSE) != 0 ||
        (desiredAccess & (DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                          FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                          WRITE_DAC | WRITE_OWNER)) != 0) {
        return TRUE;
    }

    return disposition == FILE_OVERWRITE ||
           disposition == FILE_OVERWRITE_IF ||
           disposition == FILE_SUPERSEDE;
}

static BOOLEAN
YcpIsProtectedSetInformationClass(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    if (InformationClass == FileDispositionInformation ||
        InformationClass == FileRenameInformation ||
        InformationClass == FileLinkInformation ||
        InformationClass == FileEndOfFileInformation ||
        InformationClass == FileAllocationInformation ||
        InformationClass == FileValidDataLengthInformation ||
        InformationClass == FileReplaceCompletionInformation) {
        return TRUE;
    }

#if (NTDDI_VERSION >= NTDDI_WIN10)
    if (InformationClass == FileDispositionInformationEx ||
        InformationClass == FileRenameInformationEx ||
        InformationClass == FileLinkInformationEx) {
        return TRUE;
    }
#endif

    return FALSE;
}

static BOOLEAN
YcpDestinationIsProtected(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN Resolved
    )
{
    FILE_INFORMATION_CLASS informationClass;
    PVOID information;
    HANDLE rootDirectory;
    PWSTR fileName;
    ULONG fileNameLength;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    NTSTATUS status;
    BOOLEAN protected = FALSE;

    if (Resolved != NULL) *Resolved = FALSE;

    informationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    information = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    if (information == NULL || FltObjects == NULL || FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return FALSE;
    }

    if (informationClass == FileRenameInformation ||
        informationClass == FileRenameInformationEx) {
        PFILE_RENAME_INFORMATION renameInformation = (PFILE_RENAME_INFORMATION)information;
        rootDirectory = renameInformation->RootDirectory;
        fileName = &renameInformation->FileName[0];
        fileNameLength = renameInformation->FileNameLength;
    } else if (informationClass == FileLinkInformation ||
               informationClass == FileLinkInformationEx) {
        PFILE_LINK_INFORMATION linkInformation = (PFILE_LINK_INFORMATION)information;
        rootDirectory = linkInformation->RootDirectory;
        fileName = &linkInformation->FileName[0];
        fileNameLength = linkInformation->FileNameLength;
    } else {
        return FALSE;
    }

    if (fileNameLength == 0 || fileNameLength > MAXUSHORT ||
        (fileNameLength % sizeof(WCHAR)) != 0) {
        return FALSE;
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        FltObjects->FileObject,
        rootDirectory,
        fileName,
        fileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &destination);

    if (NT_SUCCESS(status) && destination != NULL) {
        if (Resolved != NULL) *Resolved = TRUE;
        protected = YcpShouldProtectFile(&destination->Name);
        FltReleaseFileNameInformation(destination);
    }
    return protected;
}

static BOOLEAN
YcpFileSystemControlRequestsMutation(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ULONG code;

    if (Data == NULL || Data->Iopb == NULL || Data->Iopb->MajorFunction != IRP_MJ_FILE_SYSTEM_CONTROL) {
        return FALSE;
    }
    code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    return code == FSCTL_SET_REPARSE_POINT || code == FSCTL_DELETE_REPARSE_POINT;
}

static BOOLEAN
YcpTrustedNamespaceMutationAllowed(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ BOOLEAN SourceProtected,
    _In_ BOOLEAN DestinationProtected,
    _In_ BOOLEAN DestinationResolved
    )
{
    if (!YcpIsNamespaceMutation(Data) ||
        Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
        return FALSE;
    }
    // A trusted content writer may rename/link only inside the already
    // identified product namespace.  This prevents the service itself from
    // creating an alias which later bypasses the stream context.
    return SourceProtected && DestinationResolved && DestinationProtected;
}

static FLT_PREOP_CALLBACK_STATUS
YcpDenyMutation(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS
YcpPreOperationFile(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInformation = NULL;
    NTSTATUS status;
    BOOLEAN sourceProtected = FALSE;
    BOOLEAN destinationProtected = FALSE;
    BOOLEAN sourceResolved = FALSE;
    BOOLEAN destinationResolved = TRUE;
    BOOLEAN mutation = FALSE;
    BOOLEAN trustedWriter;
    BOOLEAN streamProtected;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || Data->Iopb == NULL || !YcpProtectionIsActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        mutation = YcpCreateRequestsMutation(Data);
        break;

    case IRP_MJ_WRITE:
        // Cache-manager paging writes cannot be attributed to the original
        // authorized writer. Denying them risks corrupting legitimate data.
        if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) != 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        mutation = TRUE;
        break;

    case IRP_MJ_SET_INFORMATION:
        if (YcpIsProtectedSetInformationClass(
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass)) {
            mutation = TRUE;
        }
        break;

    case IRP_MJ_FILE_SYSTEM_CONTROL:
        mutation = YcpFileSystemControlRequestsMutation(Data);
        break;

    default:
        mutation = FALSE;
        break;
    }
    if (!mutation) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    streamProtected = YcpStreamIsProtected(FltObjects);
    sourceProtected = streamProtected;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInformation);
    if (NT_SUCCESS(status) && nameInformation != NULL) {
        status = FltParseFileNameInformation(nameInformation);
        if (NT_SUCCESS(status)) {
            sourceResolved = TRUE;
            sourceProtected = sourceProtected || YcpShouldProtectFile(&nameInformation->Name);
        }
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
         Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx ||
         Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileLinkInformation ||
         Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileLinkInformationEx)) {
        destinationProtected = YcpDestinationIsProtected(Data, FltObjects, &destinationResolved);
    }

    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }

    trustedWriter = YcpIsTrustedWriter(Data);
    if (trustedWriter && !YcpIsNamespaceMutation(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    // Never deny unrelated or unresolved filesystem operations globally.
    // Unresolved aliases require file/stream identity tracking before they can
    // safely be protected; a missing name is not proof of product ownership.
    if ((sourceResolved && sourceProtected) || streamProtected ||
        (destinationResolved && destinationProtected)) {
        if (trustedWriter && YcpTrustedNamespaceMutationAllowed(
                Data,
                sourceProtected,
                destinationProtected,
                destinationResolved)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        return YcpDenyMutation(Data);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS
YcpPostOperationFile(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PFLT_FILE_NAME_INFORMATION nameInformation = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (Data == NULL || FltObjects == NULL ||
        !NT_SUCCESS(Data->IoStatus.Status) || !YcpProtectionIsActive()) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInformation);
    if (NT_SUCCESS(status) && nameInformation != NULL) {
        status = FltParseFileNameInformation(nameInformation);
        if (NT_SUCCESS(status) && YcpShouldProtectFile(&nameInformation->Name)) {
            (void)YcpMarkProtectedStream(FltObjects);
        }
        FltReleaseFileNameInformation(nameInformation);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static NTSTATUS
YcpFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    return YcpFilterUnloadAuthorized(Flags);
}

static const FLT_OPERATION_REGISTRATION g_YcpFilterOperations[] = {
    { IRP_MJ_CREATE, 0, YcpPreOperationFile, YcpPostOperationFile },
    { IRP_MJ_WRITE, 0, YcpPreOperationFile, NULL },
    { IRP_MJ_SET_INFORMATION, 0, YcpPreOperationFile, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, YcpPreOperationFile, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION g_YcpFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    g_YcpContextRegistration,
    g_YcpFilterOperations,
    YcpFilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
