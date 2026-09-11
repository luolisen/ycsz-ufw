#include "ycsz_protection.h"

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
    switch (InformationClass) {
    case FileDispositionInformation:
    case FileRenameInformation:
    case FileLinkInformation:
    case FileEndOfFileInformation:
    case FileAllocationInformation:
    case FileValidDataLengthInformation:
    case FileReplaceCompletionInformation:
        return TRUE;

#if (NTDDI_VERSION >= NTDDI_WIN10)
    case FileDispositionInformationEx:
    case FileRenameInformationEx:
    case FileLinkInformationEx:
        return TRUE;
#endif

    default:
        return FALSE;
    }
}

static BOOLEAN
YcpDestinationIsProtected(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
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
        protected = YcpShouldProtectFile(&destination->Name);
        FltReleaseFileNameInformation(destination);
    }
    return protected;
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
    BOOLEAN mutation = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || Data->Iopb == NULL ||
        Data->RequestorMode == KernelMode ||
        !YcpProtectionIsActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInformation);
    if (NT_SUCCESS(status) && nameInformation != NULL) {
        status = FltParseFileNameInformation(nameInformation);
        if (NT_SUCCESS(status)) {
            sourceProtected = YcpShouldProtectFile(&nameInformation->Name);
        }
    }

    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        mutation = YcpCreateRequestsMutation(Data);
        break;

    case IRP_MJ_WRITE:
        mutation = TRUE;
        break;

    case IRP_MJ_SET_INFORMATION:
        if (YcpIsProtectedSetInformationClass(
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass)) {
            destinationProtected = YcpDestinationIsProtected(Data, FltObjects);
            mutation = sourceProtected || destinationProtected;
        }
        break;

    default:
        break;
    }

    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }

    return (sourceProtected || destinationProtected) && mutation
        ? YcpDenyMutation(Data)
        : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS
YcpFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    return YcpFilterUnloadAuthorized(Flags);
}

static const FLT_OPERATION_REGISTRATION g_YcpFilterOperations[] = {
    { IRP_MJ_CREATE, 0, YcpPreOperationFile, NULL },
    { IRP_MJ_WRITE, 0, YcpPreOperationFile, NULL },
    { IRP_MJ_SET_INFORMATION, 0, YcpPreOperationFile, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION g_YcpFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    NULL,
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
