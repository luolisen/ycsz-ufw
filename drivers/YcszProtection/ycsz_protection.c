#include "ycsz_protection.h"
#include <ntstrsafe.h>
#include <wdmsec.h>

C_ASSERT(sizeof(WCHAR) == 2);
C_ASSERT(sizeof(YCP_CONTROL_HEADER) == 16);
C_ASSERT(sizeof(YCP_PROCESS_IDENTITY) == 1088);
C_ASSERT(sizeof(YCP_ACTIVATE_REQUEST) == 2128);
C_ASSERT(sizeof(YCP_MAINTENANCE_REQUEST) == 40);
C_ASSERT(sizeof(YCP_UNLOAD_REQUEST) == 32);
C_ASSERT(sizeof(YCP_STATUS) == 2152);

typedef struct _YCP_RUNTIME_STATE {
    EX_PUSH_LOCK Lock;
    PEPROCESS TargetProcess;
    ULONG TargetPid;
    LONGLONG TargetCreateTime100ns;
    UNICODE_STRING ImagePath;
    UNICODE_STRING ProtectedRoot;
    UCHAR ImageSha256[32];
    UCHAR InstanceNonce[16];
    UCHAR LeaseId[16];
    LONGLONG LeaseExpiresAt100ns;
    ULONGLONG LastRequestId;
    ULONG LastStatus;
    BOOLEAN Active;
    BOOLEAN Maintenance;
    BOOLEAN UnloadPrepared;
    BOOLEAN ObRegistered;
    BOOLEAN FilterStarted;
    BOOLEAN Unloading;
    ULONG OpenFileObjects;
} YCP_RUNTIME_STATE;

static YCP_RUNTIME_STATE g_YcpState;
static PDEVICE_OBJECT g_YcpDeviceObject;
static PFLT_FILTER g_YcpFilter;
static PVOID g_YcpObRegistrationHandle;

static const GUID g_YcpDeviceClassGuid =
    { 0x8c4a5cb1, 0x89cb, 0x4cf5, { 0x9f, 0xa9, 0x8a, 0x69, 0x7e, 0x5d, 0x0e, 0x42 } };

static OB_PREOP_CALLBACK_STATUS
YcpPreOperation(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

static VOID
YcpCleanup(
    _In_ BOOLEAN UnregisterFilter
    );

static NTSTATUS
YcpUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

static NTSTATUS
YcpCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

static NTSTATUS
YcpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

static const UNICODE_STRING g_YcpAltitude = RTL_CONSTANT_STRING(L"385200.1234");

static OB_OPERATION_REGISTRATION g_YcpObOperations[] = {
    {
        NULL,
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        YcpPreOperation,
        NULL
    }
};

static OB_CALLBACK_REGISTRATION g_YcpObRegistrationConfig = {
    OB_FLT_REGISTRATION_VERSION,
    1,
    { 0 },
    NULL,
    g_YcpObOperations
};

static BOOLEAN
YcpIsZeroBytes(
    _In_reads_bytes_(Length) const UCHAR *Bytes,
    _In_ SIZE_T Length
    )
{
    SIZE_T i;
    for (i = 0; i < Length; ++i) {
        if (Bytes[i] != 0) {
            return FALSE;
        }
    }
    return TRUE;
}

static NTSTATUS
YcpFixedString(
    _In_reads_(MaximumCharacters) const WCHAR *Buffer,
    _In_ USHORT MaximumCharacters,
    _Out_ PUNICODE_STRING String
    )
{
    USHORT characters = 0;

    if (Buffer == NULL || String == NULL || MaximumCharacters == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    while (characters < MaximumCharacters && Buffer[characters] != L'\0') {
        ++characters;
    }

    if (characters == 0 || characters == MaximumCharacters) {
        return STATUS_INVALID_PARAMETER;
    }

    String->Buffer = (PWCH)Buffer;
    String->Length = (USHORT)(characters * sizeof(WCHAR));
    String->MaximumLength = (USHORT)((characters + 1) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static NTSTATUS
YcpCopyString(
    _In_ PUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
    )
{
    PWCH buffer;

    if (Source == NULL || Destination == NULL || Source->Length == 0 ||
        Source->Length > (YCP_MAX_PATH_CHARS - 1) * sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    buffer = (PWCH)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        Source->Length + sizeof(WCHAR),
        YCP_POOL_TAG);
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, Source->Length + sizeof(WCHAR));
    RtlCopyMemory(buffer, Source->Buffer, Source->Length);
    Destination->Buffer = buffer;
    Destination->Length = Source->Length;
    Destination->MaximumLength = (USHORT)(Source->Length + sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static VOID
YcpFreeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, YCP_POOL_TAG);
    }
    RtlZeroMemory(String, sizeof(*String));
}

static BOOLEAN
YcpPathHasBoundaryPrefix(
    _In_ PUNICODE_STRING Root,
    _In_ PUNICODE_STRING Path
    )
{
    USHORT rootCharacters;

    if (Root == NULL || Path == NULL || Root->Length > Path->Length ||
        !RtlPrefixUnicodeString(Root, Path, TRUE)) {
        return FALSE;
    }

    if (Root->Length == Path->Length) {
        return TRUE;
    }

    rootCharacters = (USHORT)(Root->Length / sizeof(WCHAR));
    return Path->Buffer[rootCharacters] == L'\\';
}

static BOOLEAN
YcpImageMatchesRoot(
    _In_ PUNICODE_STRING Root,
    _In_ PUNICODE_STRING Image
    )
{
    static const UNICODE_STRING imageName = RTL_CONSTANT_STRING(L"Ycsz.exe");
    UNICODE_STRING suffix;
    USHORT rootCharacters;

    if (!YcpPathHasBoundaryPrefix(Root, Image) || Root->Length == Image->Length) {
        return FALSE;
    }

    rootCharacters = (USHORT)(Root->Length / sizeof(WCHAR));
    suffix.Buffer = Image->Buffer + rootCharacters + 1;
    suffix.Length = (USHORT)(Image->Length - Root->Length - sizeof(WCHAR));
    suffix.MaximumLength = suffix.Length;
    return RtlEqualUnicodeString(&imageName, &suffix, TRUE);
}

static PEPROCESS
YcpRequestorProcess(
    _In_ PIRP Irp
    )
{
    PEPROCESS process = IoGetRequestorProcess(Irp);
    return process != NULL ? process : PsGetCurrentProcess();
}

static BOOLEAN
YcpTargetMatchesLocked(
    _In_ PEPROCESS ProcessObject
    )
{
    if (g_YcpState.TargetProcess == NULL || ProcessObject != g_YcpState.TargetProcess) {
        return FALSE;
    }

    if ((ULONG)(ULONG_PTR)PsGetProcessId(ProcessObject) != g_YcpState.TargetPid) {
        return FALSE;
    }

    return PsGetProcessCreateTimeQuadPart(ProcessObject) == g_YcpState.TargetCreateTime100ns;
}

static BOOLEAN
YcpLeaseValidLocked(
    VOID
    )
{
    LARGE_INTEGER now;

    if (!g_YcpState.Maintenance) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    return now.QuadPart < g_YcpState.LeaseExpiresAt100ns;
}

static VOID
YcpClearTargetLocked(
    VOID
    )
{
    PEPROCESS oldProcess = g_YcpState.TargetProcess;

    g_YcpState.TargetProcess = NULL;
    g_YcpState.TargetPid = 0;
    g_YcpState.TargetCreateTime100ns = 0;
    g_YcpState.Active = FALSE;
    g_YcpState.Maintenance = FALSE;
    g_YcpState.UnloadPrepared = FALSE;
    g_YcpState.LeaseExpiresAt100ns = 0;
    RtlZeroMemory(g_YcpState.LeaseId, sizeof(g_YcpState.LeaseId));
    RtlZeroMemory(g_YcpState.ImageSha256, sizeof(g_YcpState.ImageSha256));
    RtlZeroMemory(g_YcpState.InstanceNonce, sizeof(g_YcpState.InstanceNonce));
    YcpFreeString(&g_YcpState.ImagePath);
    YcpFreeString(&g_YcpState.ProtectedRoot);

    if (oldProcess != NULL) {
        ObDereferenceObject(oldProcess);
    }
}

static ULONG
YcpCurrentStateLocked(
    VOID
    )
{
    ULONG state = 0;

    if (g_YcpState.Active) {
        state |= YCP_STATE_ACTIVE;
    }
    if (g_YcpState.ObRegistered) {
        state |= YCP_STATE_PROCESS_CALLBACK;
    }
    if (g_YcpState.FilterStarted) {
        state |= YCP_STATE_FILE_FILTER;
    }
    if (YcpLeaseValidLocked()) {
        state |= YCP_STATE_MAINTENANCE;
    }
    if (g_YcpState.UnloadPrepared && YcpLeaseValidLocked()) {
        state |= YCP_STATE_UNLOAD_PREPARED;
    }
    if (!g_YcpState.ObRegistered || !g_YcpState.FilterStarted) {
        state |= YCP_STATE_ERROR;
    }
    return state;
}

static VOID
YcpBuildStatusLocked(
    _Out_ YCP_STATUS *Status
    )
{
    RtlZeroMemory(Status, sizeof(*Status));
    Status->Size = sizeof(*Status);
    Status->Version = YCP_PROTOCOL_VERSION;
    Status->State = YcpCurrentStateLocked();
    Status->LastStatus = g_YcpState.LastStatus;
    Status->TargetPid = g_YcpState.TargetPid;
    Status->TargetCreateTime100ns = g_YcpState.TargetCreateTime100ns;
    Status->MaintenanceExpiresAt100ns = g_YcpState.LeaseExpiresAt100ns;
    RtlCopyMemory(Status->LeaseId, g_YcpState.LeaseId, sizeof(Status->LeaseId));
    RtlCopyMemory(Status->ImageSha256, g_YcpState.ImageSha256, sizeof(Status->ImageSha256));
    RtlCopyMemory(Status->InstanceNonce, g_YcpState.InstanceNonce, sizeof(Status->InstanceNonce));
    if (g_YcpState.ImagePath.Buffer != NULL) {
        RtlCopyMemory(Status->ImagePath, g_YcpState.ImagePath.Buffer, g_YcpState.ImagePath.Length);
    }
    if (g_YcpState.ProtectedRoot.Buffer != NULL) {
        RtlCopyMemory(Status->ProtectedRoot, g_YcpState.ProtectedRoot.Buffer, g_YcpState.ProtectedRoot.Length);
    }
}

static NTSTATUS
YcpValidateHeader(
    _In_ const YCP_CONTROL_HEADER *Header,
    _In_ ULONG ExpectedSize
    )
{
    if (Header == NULL || Header->Size != ExpectedSize ||
        Header->Version != YCP_PROTOCOL_VERSION || Header->RequestId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

// Required provisioning contract for the future signed installer (not yet wired). These values
// are never taken from an IOCTL and remain fixed for this driver lifetime.
static WCHAR g_YcpTrustedImageBuffer[YCP_MAX_PATH_CHARS];
static UNICODE_STRING g_YcpTrustedImage;
static const UCHAR g_YcpServiceSid[] = {
    0x01,0x06,0x00,0x00,0x00,0x00,0x00,0x05,0x50,0x00,0x00,0x00,
    0xca,0x29,0xbe,0x68,0x10,0x95,0x9d,0x61,0xa6,0x77,0xb3,0xba,
    0xf2,0x38,0x14,0xd7,0xfd,0xd7,0xa1,0x75
};

static NTSTATUS
YcpLoadTrustedImage(_In_ PUNICODE_STRING RegistryPath)
{
    HANDLE serviceKey = NULL;
    HANDLE parametersKey = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING parameters = RTL_CONSTANT_STRING(L"Parameters");
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"TrustedImagePath");
    UNICODE_STRING devicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
    PKEY_VALUE_PARTIAL_INFORMATION value;
    ULONG length = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(g_YcpTrustedImageBuffer);
    ULONG returned = 0;
    NTSTATUS status;
    value = ExAllocatePoolWithTag(PagedPool, length, YCP_POOL_TAG);
    if (value == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    InitializeObjectAttributes(&attributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&serviceKey, KEY_READ, &attributes);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &parameters, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, serviceKey, NULL);
        status = ZwOpenKey(&parametersKey, KEY_QUERY_VALUE, &attributes);
    }
    if (NT_SUCCESS(status)) {
        status = ZwQueryValueKey(parametersKey, &valueName, KeyValuePartialInformation, value, length, &returned);
    }
    if (NT_SUCCESS(status)) {
        if (returned < FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) || value->Type != REG_SZ ||
            value->DataLength < 2 * sizeof(WCHAR) || value->DataLength > sizeof(g_YcpTrustedImageBuffer) ||
            value->DataLength > returned - FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) ||
            value->DataLength % sizeof(WCHAR) != 0) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            RtlCopyMemory(g_YcpTrustedImageBuffer, value->Data, value->DataLength);
            status = YcpFixedString(g_YcpTrustedImageBuffer, (USHORT)(value->DataLength / sizeof(WCHAR)), &g_YcpTrustedImage);
            if (NT_SUCCESS(status) && (g_YcpTrustedImage.Length + sizeof(WCHAR) != value->DataLength ||
                !RtlPrefixUnicodeString(&devicePrefix, &g_YcpTrustedImage, TRUE))) status = STATUS_INVALID_PARAMETER;
        }
    }
    if (parametersKey != NULL) ZwClose(parametersKey);
    if (serviceKey != NULL) ZwClose(serviceKey);
    ExFreePoolWithTag(value, YCP_POOL_TAG);
    return status;
}

static BOOLEAN
YcpHasServiceIdentity(_In_ PEPROCESS Caller)
{
    PACCESS_TOKEN token;
    PTOKEN_GROUPS groups = NULL;
    PTOKEN_USER user = NULL;
    BOOLEAN allowed = FALSE;
    ULONG index;
    static const UCHAR systemSid[] = { 1,1,0,0,0,0,0,5,18,0,0,0 };
    if (PsGetProcessSessionId(Caller) != 0) return FALSE;
    token = PsReferencePrimaryToken(Caller);
    if (NT_SUCCESS(SeQueryInformationToken(token, TokenUser, (PVOID *)&user)) &&
        RtlEqualSid(user->User.Sid, (PSID)systemSid) &&
        NT_SUCCESS(SeQueryInformationToken(token, TokenGroups, (PVOID *)&groups))) {
        for (index = 0; index < groups->GroupCount; ++index) {
            if ((groups->Groups[index].Attributes & SE_GROUP_ENABLED) != 0 &&
                (groups->Groups[index].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0 &&
                RtlEqualSid(groups->Groups[index].Sid, (PSID)g_YcpServiceSid)) {
                allowed = TRUE;
                break;
            }
        }
    }
    if (groups != NULL) ExFreePool(groups);
    if (user != NULL) ExFreePool(user);
    PsDereferencePrimaryToken(token);
    return allowed;
}

static NTSTATUS
YcpValidateIdentity(
    _In_ PEPROCESS Caller,
    _In_ const YCP_PROCESS_IDENTITY *Identity,
    _In_ const WCHAR *ProtectedRoot,
    _Out_ PUNICODE_STRING ImagePath,
    _Out_ PUNICODE_STRING RootPath
    )
{
    NTSTATUS status;
    UNICODE_STRING requestedImage;
    UNICODE_STRING requestedRoot;
    PUNICODE_STRING locatedImage = NULL;

    RtlZeroMemory(ImagePath, sizeof(*ImagePath));
    RtlZeroMemory(RootPath, sizeof(*RootPath));

    if (Caller == NULL || Identity == NULL || !YcpHasServiceIdentity(Caller) ||
        Identity->ProcessId != (ULONG)(ULONG_PTR)PsGetProcessId(Caller) ||
        Identity->Reserved != 0 ||
        Identity->CreateTime100ns != PsGetProcessCreateTimeQuadPart(Caller) ||
        YcpIsZeroBytes(Identity->InstanceNonce, sizeof(Identity->InstanceNonce)) ||
        YcpIsZeroBytes(Identity->ImageSha256, sizeof(Identity->ImageSha256))) {
        return STATUS_ACCESS_DENIED;
    }

    status = YcpFixedString(Identity->ImagePath, YCP_MAX_PATH_CHARS, &requestedImage);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = YcpFixedString(ProtectedRoot, YCP_MAX_PATH_CHARS, &requestedRoot);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(Caller, &locatedImage);
    if (!NT_SUCCESS(status) || locatedImage == NULL ||
        !RtlEqualUnicodeString(&requestedImage, locatedImage, TRUE) ||
        !RtlEqualUnicodeString(&g_YcpTrustedImage, locatedImage, TRUE) ||
        !YcpImageMatchesRoot(&requestedRoot, locatedImage)) {
        if (locatedImage != NULL) {
            ExFreePool(locatedImage);
        }
        return STATUS_ACCESS_DENIED;
    }

    status = YcpCopyString(&requestedImage, ImagePath);
    if (NT_SUCCESS(status)) {
        status = YcpCopyString(&requestedRoot, RootPath);
    }
    if (locatedImage != NULL) {
        ExFreePool(locatedImage);
    }
    if (!NT_SUCCESS(status)) {
        YcpFreeString(ImagePath);
        YcpFreeString(RootPath);
    }
    return status;
}

static NTSTATUS
YcpActivate(
    _In_ PEPROCESS Caller,
    _In_ const YCP_ACTIVATE_REQUEST *Request
    )
{
    NTSTATUS status;
    UNICODE_STRING imagePath;
    UNICODE_STRING rootPath;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = YcpValidateIdentity(
        Caller,
        &Request->Identity,
        Request->ProtectedRoot,
        &imagePath,
        &rootPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    if (g_YcpState.Unloading || (g_YcpState.TargetProcess != NULL && g_YcpState.TargetProcess != Caller &&
        PsGetProcessExitStatus(g_YcpState.TargetProcess) == STATUS_PENDING)) {
        ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
        YcpFreeString(&imagePath);
        YcpFreeString(&rootPath);
        return STATUS_DEVICE_BUSY;
    }

    if (g_YcpState.TargetProcess != NULL) {
        YcpClearTargetLocked();
    }

    g_YcpState.TargetProcess = Caller;
    ObReferenceObject(Caller);
    g_YcpState.TargetPid = Request->Identity.ProcessId;
    g_YcpState.TargetCreateTime100ns = Request->Identity.CreateTime100ns;
    g_YcpState.ImagePath = imagePath;
    g_YcpState.ProtectedRoot = rootPath;
    RtlCopyMemory(g_YcpState.ImageSha256, Request->Identity.ImageSha256, sizeof(g_YcpState.ImageSha256));
    RtlCopyMemory(g_YcpState.InstanceNonce, Request->Identity.InstanceNonce, sizeof(g_YcpState.InstanceNonce));
    g_YcpState.LeaseExpiresAt100ns = 0;
    RtlZeroMemory(g_YcpState.LeaseId, sizeof(g_YcpState.LeaseId));
    g_YcpState.Maintenance = FALSE;
    g_YcpState.UnloadPrepared = FALSE;
    g_YcpState.Active = TRUE;
    g_YcpState.LastRequestId = Request->Header.RequestId;
    g_YcpState.LastStatus = STATUS_SUCCESS;
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

static NTSTATUS
YcpValidateCallerLocked(
    _In_ PEPROCESS Caller
    )
{
    return !g_YcpState.Unloading && YcpTargetMatchesLocked(Caller) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

static NTSTATUS
YcpEnterMaintenance(
    _In_ PEPROCESS Caller,
    _In_ const YCP_MAINTENANCE_REQUEST *Request
    )
{
    LARGE_INTEGER now;
    LONGLONG maximumExpiry;
    NTSTATUS status;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status) || YcpIsZeroBytes(Request->LeaseId, sizeof(Request->LeaseId))) {
        return STATUS_INVALID_PARAMETER;
    }

    KeQuerySystemTime(&now);
    maximumExpiry = now.QuadPart + ((LONGLONG)YCP_MAX_LEASE_SECONDS * 10000000LL);
    if (Request->ExpiresAt100ns <= now.QuadPart || Request->ExpiresAt100ns > maximumExpiry) {
        return STATUS_TIMEOUT;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status)) {
        if (g_YcpState.LastRequestId == Request->Header.RequestId) {
            status = STATUS_INVALID_PARAMETER;
        } else if (YcpLeaseValidLocked()) {
            status = STATUS_DEVICE_BUSY;
        } else {
            RtlCopyMemory(g_YcpState.LeaseId, Request->LeaseId, sizeof(g_YcpState.LeaseId));
            g_YcpState.LeaseExpiresAt100ns = Request->ExpiresAt100ns;
            g_YcpState.Maintenance = TRUE;
            g_YcpState.UnloadPrepared = FALSE;
            g_YcpState.LastRequestId = Request->Header.RequestId;
            g_YcpState.LastStatus = STATUS_SUCCESS;
        }
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
YcpExitMaintenance(
    _In_ PEPROCESS Caller,
    _In_ const YCP_MAINTENANCE_REQUEST *Request
    )
{
    NTSTATUS status;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status)) {
        if (g_YcpState.LastRequestId == Request->Header.RequestId ||
            !g_YcpState.Maintenance ||
            !RtlEqualMemory(g_YcpState.LeaseId, Request->LeaseId, sizeof(g_YcpState.LeaseId))) {
            status = STATUS_ACCESS_DENIED;
        } else {
            g_YcpState.Maintenance = FALSE;
            g_YcpState.UnloadPrepared = FALSE;
            g_YcpState.LeaseExpiresAt100ns = 0;
            RtlZeroMemory(g_YcpState.LeaseId, sizeof(g_YcpState.LeaseId));
            g_YcpState.LastRequestId = Request->Header.RequestId;
            g_YcpState.LastStatus = STATUS_SUCCESS;
        }
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
YcpPrepareUnload(
    _In_ PEPROCESS Caller,
    _In_ const YCP_UNLOAD_REQUEST *Request
    )
{
    NTSTATUS status;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status)) {
        if (g_YcpState.LastRequestId == Request->Header.RequestId ||
            !YcpLeaseValidLocked() ||
            !RtlEqualMemory(g_YcpState.LeaseId, Request->LeaseId, sizeof(g_YcpState.LeaseId))) {
            status = STATUS_ACCESS_DENIED;
        } else {
            g_YcpState.UnloadPrepared = TRUE;
            g_YcpState.LastRequestId = Request->Header.RequestId;
            g_YcpState.LastStatus = STATUS_SUCCESS;
        }
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
YcpQueryStatus(
    _In_ PEPROCESS Caller,
    _Out_ YCP_STATUS *Status
    )
{
    NTSTATUS result = STATUS_SUCCESS;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    if (g_YcpState.Active && !YcpTargetMatchesLocked(Caller)) {
        result = STATUS_ACCESS_DENIED;
    } else {
        YcpBuildStatusLocked(Status);
    }
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return result;
}

NTSTATUS
YcpCompleteIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

BOOLEAN
YcpProtectionIsActive(
    VOID
    )
{
    BOOLEAN active;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    active = g_YcpState.Active && !YcpLeaseValidLocked();
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return active;
}

BOOLEAN
YcpMaintenanceIsActive(
    VOID
    )
{
    BOOLEAN active;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    active = YcpLeaseValidLocked();
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return active;
}

BOOLEAN
YcpShouldProtectProcess(
    _In_ PEPROCESS ProcessObject
    )
{
    BOOLEAN protect;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    protect = g_YcpState.Active && !YcpLeaseValidLocked() && YcpTargetMatchesLocked(ProcessObject);
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return protect;
}

BOOLEAN
YcpShouldProtectFile(
    _In_ PUNICODE_STRING NormalizedName
    )
{
    BOOLEAN protect;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    protect = g_YcpState.Active && !YcpLeaseValidLocked() &&
        g_YcpState.ProtectedRoot.Buffer != NULL &&
        YcpPathHasBoundaryPrefix(&g_YcpState.ProtectedRoot, NormalizedName);
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return protect;
}

static NTSTATUS
YcpCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    UNREFERENCED_PARAMETER(DeviceObject);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    if (stack->MajorFunction == IRP_MJ_CREATE) {
        if (g_YcpState.Unloading) {
            status = STATUS_DELETE_PENDING;
        } else if (stack->FileObject == NULL || stack->FileObject->FsContext != NULL ||
                   g_YcpState.OpenFileObjects == MAXULONG) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            // Count file objects, not handles: duplicated handles keep this
            // reference until the final CLOSE, including outstanding I/O.
            stack->FileObject->FsContext = &g_YcpState;
            ++g_YcpState.OpenFileObjects;
            information = FILE_OPENED;
        }
    } else if (stack->MajorFunction == IRP_MJ_CLOSE && stack->FileObject != NULL &&
               stack->FileObject->FsContext == &g_YcpState) {
        stack->FileObject->FsContext = NULL;
        NT_ASSERT(g_YcpState.OpenFileObjects != 0);
        if (g_YcpState.OpenFileObjects != 0) --g_YcpState.OpenFileObjects;
    }
    // CLEANUP succeeds but retains the reference. It is too early to permit
    // unload while the I/O manager still owns this file object.
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return YcpCompleteIrp(Irp, status, information);
}

static NTSTATUS
YcpUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return YcpCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS
YcpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    PEPROCESS caller;
    PVOID buffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG_PTR information = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    caller = YcpRequestorProcess(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (buffer == NULL) {
        return YcpCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_YCP_ACTIVATE:
        if (inputLength < sizeof(YCP_ACTIVATE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpActivate(caller, (const YCP_ACTIVATE_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_ENTER_MAINTENANCE:
        if (inputLength < sizeof(YCP_MAINTENANCE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpEnterMaintenance(caller, (const YCP_MAINTENANCE_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_EXIT_MAINTENANCE:
        if (inputLength < sizeof(YCP_MAINTENANCE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpExitMaintenance(caller, (const YCP_MAINTENANCE_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_PREPARE_UNLOAD:
        if (inputLength < sizeof(YCP_UNLOAD_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpPrepareUnload(caller, (const YCP_UNLOAD_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_QUERY_STATUS:
        if (outputLength < sizeof(YCP_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpQueryStatus(caller, (YCP_STATUS *)buffer);
            if (NT_SUCCESS(status)) {
                information = sizeof(YCP_STATUS);
            }
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    if (!NT_SUCCESS(status)) {
        g_YcpState.LastStatus = status;
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return YcpCompleteIrp(Irp, status, information);
}

static VOID
YcpCleanup(
    _In_ BOOLEAN UnregisterFilter
    )
{
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(YCP_DEVICE_DOS_NAME);

    // Flt Manager owns the filter object while it is executing the unload
    // callback.  Calling FltUnregisterFilter from that callback would race or
    // recurse into the same unload path.  DriverEntry failure paths pass TRUE;
    // the actual FilterUnload callback passes FALSE and lets Flt Manager finish
    // unregistering after this callback returns.
    if (UnregisterFilter && g_YcpFilter != NULL) {
        FltUnregisterFilter(g_YcpFilter);
    }
    g_YcpFilter = NULL;
    if (g_YcpObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_YcpObRegistrationHandle);
        g_YcpObRegistrationHandle = NULL;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    g_YcpState.FilterStarted = FALSE;
    g_YcpState.ObRegistered = FALSE;
    YcpClearTargetLocked();
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();

    IoDeleteSymbolicLink(&symbolicLink);
    if (g_YcpDeviceObject != NULL) {
        IoDeleteDevice(g_YcpDeviceObject);
        g_YcpDeviceObject = NULL;
    }
}

NTSTATUS
YcpFilterUnloadAuthorized(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    BOOLEAN allowed;
    // The registration rejects service-stop unloads. Other unloads are checked
    // here, at the actual unload point, rather than by publishing DriverUnload.
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    allowed = !g_YcpState.Unloading && g_YcpState.OpenFileObjects == 0 && (!g_YcpState.Active ||
        (g_YcpState.UnloadPrepared && YcpLeaseValidLocked()));
    if ((Flags & FLTFL_FILTER_UNLOAD_MANDATORY) != 0) {
        // Mandatory unload cannot be vetoed by this callback. The supported
        // service-stop path is disabled by registration; always clean up safely.
        allowed = !g_YcpState.Unloading;
    }
    if (allowed) {
        g_YcpState.Unloading = TRUE;
        g_YcpState.UnloadPrepared = FALSE;
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    if (!allowed) return STATUS_FLT_DO_NOT_DETACH;
    YcpCleanup(FALSE);
    return STATUS_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS
YcpPreOperation(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    ACCESS_MASK *desiredAccess;
    const ACCESS_MASK deniedAccess =
        PROCESS_TERMINATE |
        PROCESS_SUSPEND_RESUME |
        PROCESS_SET_INFORMATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation == NULL || OperationInformation->KernelHandle ||
        !YcpShouldProtectProcess((PEPROCESS)OperationInformation->Object)) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    *desiredAccess &= ~deniedAccess;
    return OB_PREOP_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\YcszProtection");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(YCP_DEVICE_DOS_NAME);
    UNICODE_STRING securityDescriptor = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)");
    ULONG index;

    RtlZeroMemory(&g_YcpState, sizeof(g_YcpState));
    ExInitializePushLock(&g_YcpState.Lock);
    status = YcpLoadTrustedImage(RegistryPath);
    if (!NT_SUCCESS(status)) return status;

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        DriverObject->MajorFunction[index] = YcpUnsupported;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = YcpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = YcpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = YcpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = YcpDeviceControl;

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        YCP_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &securityDescriptor,
        &g_YcpDeviceClassGuid,
        &g_YcpDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_YcpDeviceObject);
        g_YcpDeviceObject = NULL;
        return status;
    }

    status = FltRegisterFilter(DriverObject, &g_YcpFilterRegistration, &g_YcpFilter);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_YcpDeviceObject);
        g_YcpDeviceObject = NULL;
        return status;
    }

    g_YcpObOperations[0].ObjectType = PsProcessType;
    g_YcpObRegistrationConfig.Version = OB_FLT_REGISTRATION_VERSION;
    g_YcpObRegistrationConfig.OperationRegistrationCount = RTL_NUMBER_OF(g_YcpObOperations);
    g_YcpObRegistrationConfig.RegistrationContext = NULL;
    g_YcpObRegistrationConfig.OperationRegistration = g_YcpObOperations;
    g_YcpObRegistrationConfig.Altitude = g_YcpAltitude;
    status = ObRegisterCallbacks(&g_YcpObRegistrationConfig, &g_YcpObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_YcpFilter);
        g_YcpFilter = NULL;
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_YcpDeviceObject);
        g_YcpDeviceObject = NULL;
        return status;
    }
    g_YcpState.ObRegistered = TRUE;

    status = FltStartFiltering(g_YcpFilter);
    if (!NT_SUCCESS(status)) {
        ObUnRegisterCallbacks(g_YcpObRegistrationHandle);
        g_YcpObRegistrationHandle = NULL;
        g_YcpState.ObRegistered = FALSE;
        FltUnregisterFilter(g_YcpFilter);
        g_YcpFilter = NULL;
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_YcpDeviceObject);
        g_YcpDeviceObject = NULL;
        return status;
    }
    g_YcpState.FilterStarted = TRUE;
    g_YcpDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
