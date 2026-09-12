#include "ycsz_protection.h"

typedef struct _YCP_STREAM_CONTEXT {
    ULONG Version;
    BOOLEAN ProductStream;
    LARGE_INTEGER FileId;
} YCP_STREAM_CONTEXT, *PYCP_STREAM_CONTEXT;

typedef struct _YCP_INSTANCE_CONTEXT {
    ULONG Version;
    ULONG VolumeSerialNumber;
} YCP_INSTANCE_CONTEXT, *PYCP_INSTANCE_CONTEXT;

static BOOLEAN
YcpFileSystemControlRequestsMutation(
    _In_ PFLT_CALLBACK_DATA Data
    );

static BOOLEAN
YcpCreateChangesNamespace(
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

static VOID
YcpInstanceContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

static const FLT_CONTEXT_REGISTRATION g_YcpContextRegistration[] = {
    { FLT_INSTANCE_CONTEXT, 0, YcpInstanceContextCleanup, sizeof(YCP_INSTANCE_CONTEXT), YCP_POOL_TAG },
    { FLT_STREAM_CONTEXT, 0, YcpStreamContextCleanup, sizeof(YCP_STREAM_CONTEXT), YCP_POOL_TAG },
    { FLT_CONTEXT_END }
};

static NTSTATUS
YcpInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    IO_STATUS_BLOCK ioStatus;
    struct {
        FILE_FS_VOLUME_INFORMATION Information;
        WCHAR ExtraLabel[128];
    } volumeBuffer;
    PFILE_FS_VOLUME_INFORMATION volumeInformation;
    PFLT_CONTEXT context = NULL;
    PFLT_CONTEXT oldContext = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    if (FltObjects == NULL || FltObjects->Filter == NULL || FltObjects->Instance == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&volumeBuffer, sizeof(volumeBuffer));
    volumeInformation = &volumeBuffer.Information;
    status = FltQueryVolumeInformation(
        FltObjects->Instance,
        &ioStatus,
        volumeInformation,
        sizeof(volumeBuffer),
        FileFsVolumeInformation);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_INSTANCE_CONTEXT,
        sizeof(YCP_INSTANCE_CONTEXT),
        NonPagedPoolNx,
        &context);
    if (!NT_SUCCESS(status)) return status;
    ((PYCP_INSTANCE_CONTEXT)context)->Version = 1;
    ((PYCP_INSTANCE_CONTEXT)context)->VolumeSerialNumber = volumeInformation->VolumeSerialNumber;
    status = FltSetInstanceContext(
        FltObjects->Instance,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        context,
        &oldContext);
    FltReleaseContext(context);
    if (oldContext != NULL) FltReleaseContext(oldContext);
    return NT_SUCCESS(status) || status == STATUS_FLT_CONTEXT_ALREADY_DEFINED
        ? STATUS_SUCCESS
        : status;
}

static BOOLEAN
YcpGetInstanceVolumeSerial(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG VolumeSerialNumber
    )
{
    PFLT_CONTEXT context = NULL;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->Instance == NULL || VolumeSerialNumber == NULL) {
        return FALSE;
    }
    status = FltGetInstanceContext(FltObjects->Instance, &context);
    if (!NT_SUCCESS(status) || context == NULL) return FALSE;
    *VolumeSerialNumber = ((PYCP_INSTANCE_CONTEXT)context)->VolumeSerialNumber;
    FltReleaseContext(context);
    return TRUE;
}

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
YcpAttachProtectedStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PLARGE_INTEGER FileId
    )
{
    PFLT_CONTEXT context = NULL;
    PFLT_CONTEXT oldContext = NULL;
    PFLT_FILTER filter = NULL;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL || FileId == NULL) {
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
    FltObjectDereference(filter);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    ((PYCP_STREAM_CONTEXT)context)->Version = 1;
    ((PYCP_STREAM_CONTEXT)context)->ProductStream = TRUE;
    ((PYCP_STREAM_CONTEXT)context)->FileId = *FileId;
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
YcpMarkProtectedStream(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ YCP_INITIALIZATION_FILE_IDENTITY *Identity
    )
{
    FILE_INTERNAL_INFORMATION fileInformation;
    ULONG volumeSerialNumber;
    NTSTATUS status;

    if (Identity != NULL) RtlZeroMemory(Identity, sizeof(*Identity));
    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL ||
        Identity == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
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
    if (!YcpGetInstanceVolumeSerial(FltObjects, &volumeSerialNumber)) return FALSE;
    Identity->VolumeSerialNumber = volumeSerialNumber;
    Identity->FileIndex = fileInformation.IndexNumber.QuadPart;
    return YcpAttachProtectedStreamContext(FltObjects, &fileInformation.IndexNumber);
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
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        return YcpCreateChangesNamespace(Data);
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
YcpCreateChangesNamespace(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    ULONG options;
    ULONG disposition;

    if (Data == NULL || Data->Iopb == NULL || Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FALSE;
    }
    options = Data->Iopb->Parameters.Create.Options;
    disposition = (options >> 24) & 0xff;
    return (options & FILE_DELETE_ON_CLOSE) != 0 ||
        disposition == FILE_CREATE ||
        disposition == FILE_OPEN_IF ||
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
    // CREATE has a source name but no rename/link destination. The caller
    // checks initialization and ancestor restrictions before this exception.
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        return SourceProtected;
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
    BOOLEAN namespaceAncestor = FALSE;
    BOOLEAN active;
    BOOLEAN initializing;
    BOOLEAN initializationCaptured = FALSE;
    YCP_INITIALIZATION_OBSERVATION_CONTEXT initializationSnapshot;
    FLT_PREOP_CALLBACK_STATUS result;
    FLT_PREOP_CALLBACK_STATUS allowedStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (CompletionContext != NULL) *CompletionContext = NULL;
    RtlZeroMemory(&initializationSnapshot, sizeof(initializationSnapshot));

    if (Data == NULL || Data->Iopb == NULL) {
        return allowedStatus;
    }
    active = YcpProtectionIsActive();
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        // Capture the round before doing any name work.  The post-create
        // callback must not infer its round from mutable global state later.
        initializationCaptured = YcpCaptureInitializationSnapshot(
            FltGetRequestorProcess(Data),
            &initializationSnapshot);
    }
    initializing = initializationCaptured || YcpProtectionIsInitializing();
    if (!active && !initializing) {
        return allowedStatus;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) allowedStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        mutation = YcpCreateRequestsMutation(Data) || YcpCreateChangesNamespace(Data);
        break;

    case IRP_MJ_WRITE:
        // Cache-manager paging writes cannot be attributed to the original
        // authorized writer. Denying them risks corrupting legitimate data.
        if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) != 0) {
            result = allowedStatus;
            goto Finish;
        }
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
    if (!mutation) {
        result = allowedStatus;
        goto Finish;
    }

    // Stream contexts are not available in pre-create. Resolve the name here;
    // the successful post-create callback attaches the stream identity.
    streamProtected = Data->Iopb->MajorFunction != IRP_MJ_CREATE &&
        YcpStreamIsProtected(FltObjects);
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
            namespaceAncestor = YcpIsNamespaceMutation(Data) && YcpShouldProtectAncestor(&nameInformation->Name);
        }
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
         Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx ||
         Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileLinkInformation ||
         Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileLinkInformationEx)) {
        destinationProtected = YcpDestinationIsProtected(Data, FltObjects, &destinationResolved);
    }

    // Moving or redirecting a parent invalidates both protected root paths.
    // This applies only to namespace mutations, never ordinary parent I/O.
    if (namespaceAncestor) {
        result = YcpDenyMutation(Data);
        goto Finish;
    }
    // During initialization, namespace changes are blocked only when the
    // resolved source, stream, destination, or strict ancestor is part of
    // the confirmed product namespace. Unknown/unresolved paths continue to
    // pass so this phase cannot become a global filesystem denial.
    if (initializing && YcpIsNamespaceMutation(Data)) {
        if ((sourceResolved && sourceProtected) || streamProtected ||
            (destinationResolved && destinationProtected)) {
            result = YcpDenyMutation(Data);
            goto Finish;
        }
        result = allowedStatus;
        goto Finish;
    }
    trustedWriter = YcpIsTrustedWriter(Data);
    if (trustedWriter && !YcpIsNamespaceMutation(Data)) {
        result = allowedStatus;
        goto Finish;
    }
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
            result = allowedStatus;
            goto Finish;
        }
        result = YcpDenyMutation(Data);
        goto Finish;
    }
    result = allowedStatus;

Finish:
    if (initializationCaptured) {
        if (result == FLT_PREOP_SUCCESS_WITH_CALLBACK && CompletionContext != NULL) {
            PYCP_INITIALIZATION_OBSERVATION_CONTEXT context =
                (PYCP_INITIALIZATION_OBSERVATION_CONTEXT)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    sizeof(*context),
                    YCP_POOL_TAG);
            if (context != NULL) {
                *context = initializationSnapshot;
                RtlZeroMemory(&initializationSnapshot, sizeof(initializationSnapshot));
                *CompletionContext = context;
            } else {
                // A missing completion context cannot globally deny unrelated
                // I/O, but this round must remain uncommittable.
                YcpRecordInitializationStream(
                    &initializationSnapshot,
                    NULL,
                    0,
                    FALSE);
            }
        }
        YcpReleaseInitializationSnapshot(&initializationSnapshot);
    }
    return result;
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
    PYCP_INITIALIZATION_OBSERVATION_CONTEXT initializationSnapshot =
        (PYCP_INITIALIZATION_OBSERVATION_CONTEXT)CompletionContext;
    NTSTATUS status;

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) != 0) goto Finish;

    if (Data == NULL || FltObjects == NULL ||
        !NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE ||
        (!YcpProtectionIsActive() && !YcpProtectionIsInitializing())) {
        goto Finish;
    }
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInformation);
    if (NT_SUCCESS(status) && nameInformation != NULL) {
        status = FltParseFileNameInformation(nameInformation);
        if (NT_SUCCESS(status) && YcpShouldProtectFile(&nameInformation->Name)) {
            YCP_INITIALIZATION_FILE_IDENTITY identity;
            BOOLEAN marked = YcpMarkProtectedStream(FltObjects, &identity);
            if (initializationSnapshot != NULL) {
                YcpRecordInitializationStream(
                    initializationSnapshot,
                    &identity,
                    0,
                    marked);
            }
        }
    }
Finish:
    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }
    if (initializationSnapshot != NULL) {
        YcpReleaseInitializationSnapshot(initializationSnapshot);
        ExFreePoolWithTag(initializationSnapshot, YCP_POOL_TAG);
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
    YcpInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
