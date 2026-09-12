#include "ycsz_protection.h"
#include <ntstrsafe.h>
#include <wdmsec.h>

#ifndef SE_GROUP_ENABLED
#define SE_GROUP_ENABLED ((ULONG)0x00000004L)
#endif

#ifndef SE_GROUP_USE_FOR_DENY_ONLY
#define SE_GROUP_USE_FOR_DENY_ONLY ((ULONG)0x00000010L)
#endif

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE ((ACCESS_MASK)0x0001)
#endif

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME ((ACCESS_MASK)0x0800)
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION ((ACCESS_MASK)0x0200)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE ((ACCESS_MASK)0x0020)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION ((ACCESS_MASK)0x0008)
#endif

C_ASSERT(sizeof(WCHAR) == 2);
C_ASSERT(sizeof(YCP_CONTROL_HEADER) == 16);
C_ASSERT(sizeof(YCP_PROCESS_IDENTITY) == 1088);
C_ASSERT(sizeof(YCP_ACTIVATE_REQUEST) == 3160);
C_ASSERT(sizeof(YCP_INITIALIZE_COMMIT_REQUEST) == 40);
C_ASSERT(sizeof(YCP_INITIALIZE_ABORT_REQUEST) == 32);
C_ASSERT(sizeof(YCP_INITIALIZATION_FILE_IDENTITY) == 16);
C_ASSERT(sizeof(YCP_INITIALIZATION_ENTRY_REQUEST) == 56);
C_ASSERT(sizeof(YCP_TRAY_REQUEST) == 1104);
C_ASSERT(sizeof(YCP_MAINTENANCE_REQUEST) == 40);
C_ASSERT(sizeof(YCP_UNLOAD_REQUEST) == 32);
C_ASSERT(sizeof(YCP_STATUS) == 4296);

typedef struct _YCP_RUNTIME_STATE {
    EX_PUSH_LOCK Lock;
    PEPROCESS TargetProcess;
    ULONG TargetPid;
    LONGLONG TargetCreateTime100ns;
    UNICODE_STRING ImagePath;
    UNICODE_STRING ProtectedRoot;
    UNICODE_STRING ProtectedDataRoot;
    PEPROCESS TrayProcess;
    YCP_PROCESS_IDENTITY TrayIdentity;
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
    BOOLEAN Initializing;
    YCP_INITIALIZATION_COVERAGE InitializationCoverage;
    ULONG InitializationManifestEntries;
    ULONGLONG InitializationGeneration;
    LONGLONG InitializationExpiresAt100ns;
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

    buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
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
YcpPathIsStrictAncestor(
    _In_ PUNICODE_STRING Path,
    _In_ PUNICODE_STRING Root
    )
{
    return Path != NULL && Root != NULL && Path->Length != 0 &&
        Path->Length < Root->Length && YcpPathHasBoundaryPrefix(Path, Root);
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

    return PsGetProcessCreateTimeQuadPart(ProcessObject) == g_YcpState.TargetCreateTime100ns &&
        PsGetProcessExitStatus(ProcessObject) == STATUS_PENDING;
}

static BOOLEAN
YcpTrayTargetMatchesLocked(
    _In_ PEPROCESS ProcessObject
    )
{
    if (g_YcpState.TrayProcess == NULL || ProcessObject != g_YcpState.TrayProcess) {
        return FALSE;
    }

    return (ULONG)(ULONG_PTR)PsGetProcessId(ProcessObject) == g_YcpState.TrayIdentity.ProcessId &&
        PsGetProcessCreateTimeQuadPart(ProcessObject) == g_YcpState.TrayIdentity.CreateTime100ns &&
        PsGetProcessExitStatus(ProcessObject) == STATUS_PENDING;
}

static BOOLEAN
YcpIdentityEquals(
    _In_ const YCP_PROCESS_IDENTITY *Left,
    _In_ const YCP_PROCESS_IDENTITY *Right
    )
{
    return Left != NULL && Right != NULL &&
        RtlEqualMemory(Left, Right, sizeof(*Left));
}

static BOOLEAN
YcpProcessSessionMatches(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ExpectedSessionId
    )
{
    PACCESS_TOKEN token;
    PULONG sessionId = NULL;
    BOOLEAN matches = FALSE;

    token = PsReferencePrimaryToken(ProcessObject);
    if (token != NULL) {
        if (NT_SUCCESS(SeQueryInformationToken(token, TokenSessionId, (PVOID *)&sessionId)) &&
            sessionId != NULL && *sessionId == ExpectedSessionId) {
            matches = TRUE;
        }
        if (sessionId != NULL) ExFreePool(sessionId);
        PsDereferencePrimaryToken(token);
    }
    return matches;
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

static BOOLEAN
YcpInitializationValidLocked(
    VOID
    )
{
    LARGE_INTEGER now;

    if (!g_YcpState.Initializing || g_YcpState.Unloading ||
        g_YcpState.TargetProcess == NULL ||
        PsGetProcessExitStatus(g_YcpState.TargetProcess) != STATUS_PENDING) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    return now.QuadPart < g_YcpState.InitializationExpiresAt100ns;
}

BOOLEAN
YcpCaptureInitializationSnapshot(
    _In_ PEPROCESS Requestor,
    _Out_ PYCP_INITIALIZATION_OBSERVATION_CONTEXT Snapshot
    )
{
    BOOLEAN captured = FALSE;

    if (Snapshot == NULL) return FALSE;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    if (Requestor == NULL) return FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    if (YcpInitializationValidLocked() && YcpTargetMatchesLocked(Requestor)) {
        ObReferenceObject(g_YcpState.TargetProcess);
        Snapshot->OwnerProcess = g_YcpState.TargetProcess;
        Snapshot->Generation = g_YcpState.InitializationGeneration;
        RtlCopyMemory(
            Snapshot->InstanceNonce,
            g_YcpState.InstanceNonce,
            sizeof(Snapshot->InstanceNonce));
        captured = TRUE;
    }
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return captured;
}

VOID
YcpReleaseInitializationSnapshot(
    _Inout_ PYCP_INITIALIZATION_OBSERVATION_CONTEXT Snapshot
    )
{
    if (Snapshot == NULL) return;
    if (Snapshot->OwnerProcess != NULL) {
        ObDereferenceObject(Snapshot->OwnerProcess);
    }
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
}

static VOID
YcpClearInitializationCoverageLocked(
    VOID
    )
{
    if (g_YcpState.InitializationCoverage.Slots != NULL) {
        ExFreePoolWithTag(g_YcpState.InitializationCoverage.Slots, YCP_POOL_TAG);
    }
    RtlZeroMemory(&g_YcpState.InitializationCoverage, sizeof(g_YcpState.InitializationCoverage));
    g_YcpState.InitializationManifestEntries = 0;
}

static NTSTATUS
YcpAllocateInitializationCoverage(
    _In_ ULONG MaximumEntries,
    _Out_ PYCP_INITIALIZATION_COVERAGE Coverage
    )
{
    ULONG requiredSlots;
    ULONG slotCount;
    SIZE_T bytes;
    PYCP_INITIALIZATION_COVERAGE_SLOT slots;

    if (Coverage == NULL || MaximumEntries == 0 ||
        MaximumEntries > YCP_MAX_INITIALIZATION_ENTRIES) {
        return STATUS_INVALID_PARAMETER;
    }

    requiredSlots = MaximumEntries > (MAXULONG / 2u)
        ? MAXULONG
        : MaximumEntries * 2u;
    slotCount = 2u;
    while (slotCount < requiredSlots) {
        if (slotCount > (MAXULONG / 2u)) return STATUS_INVALID_PARAMETER;
        slotCount <<= 1;
    }
    bytes = (SIZE_T)slotCount * sizeof(YCP_INITIALIZATION_COVERAGE_SLOT);
    slots = (PYCP_INITIALIZATION_COVERAGE_SLOT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        bytes,
        YCP_POOL_TAG);
    if (slots == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    if (!YcpInitializationCoverageInitialize(
            Coverage,
            slots,
            slotCount,
            MaximumEntries)) {
        ExFreePoolWithTag(slots, YCP_POOL_TAG);
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static VOID
YcpFreeInitializationCoverage(
    _Inout_ PYCP_INITIALIZATION_COVERAGE Coverage
    )
{
    if (Coverage != NULL && Coverage->Slots != NULL) {
        ExFreePoolWithTag(Coverage->Slots, YCP_POOL_TAG);
        RtlZeroMemory(Coverage, sizeof(*Coverage));
    }
}

static VOID
YcpClearTrayLocked(
    VOID
    )
{
    PEPROCESS oldProcess = g_YcpState.TrayProcess;

    g_YcpState.TrayProcess = NULL;
    RtlZeroMemory(&g_YcpState.TrayIdentity, sizeof(g_YcpState.TrayIdentity));
    if (oldProcess != NULL) {
        ObDereferenceObject(oldProcess);
    }
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
    g_YcpState.Initializing = FALSE;
    g_YcpState.Maintenance = FALSE;
    g_YcpState.UnloadPrepared = FALSE;
    g_YcpState.LeaseExpiresAt100ns = 0;
    YcpClearInitializationCoverageLocked();
    g_YcpState.InitializationExpiresAt100ns = 0;
    RtlZeroMemory(g_YcpState.LeaseId, sizeof(g_YcpState.LeaseId));
    RtlZeroMemory(g_YcpState.ImageSha256, sizeof(g_YcpState.ImageSha256));
    RtlZeroMemory(g_YcpState.InstanceNonce, sizeof(g_YcpState.InstanceNonce));
    YcpFreeString(&g_YcpState.ImagePath);
    YcpFreeString(&g_YcpState.ProtectedRoot);
    YcpFreeString(&g_YcpState.ProtectedDataRoot);
    YcpClearTrayLocked();

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
    if (YcpInitializationValidLocked()) {
        state |= YCP_STATE_INITIALIZING;
    } else if (g_YcpState.Initializing) {
        state |= YCP_STATE_ERROR;
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
    if (g_YcpState.TrayProcess != NULL) {
        state |= YCP_STATE_TRAY_REGISTERED;
    }
    if (g_YcpState.ProtectedDataRoot.Buffer != NULL) {
        state |= YCP_STATE_DATA_ROOT;
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
    Status->TargetSessionId = 0;
    Status->TargetCreateTime100ns = g_YcpState.TargetCreateTime100ns;
    Status->MaintenanceExpiresAt100ns = g_YcpState.LeaseExpiresAt100ns;
    Status->InitializationExpectedEntries = g_YcpState.InitializationCoverage.DeclaredEntries;
    Status->InitializationMarkedEntries = g_YcpState.InitializationCoverage.MarkedEntries;
    Status->InitializationFailures = g_YcpState.InitializationCoverage.Failures;
    Status->InitializationUnexpectedEntries = g_YcpState.InitializationCoverage.UnexpectedEntries;
    Status->InitializationDuplicateEntries = g_YcpState.InitializationCoverage.DuplicateEntries;
    Status->InitializationExpiresAt100ns = g_YcpState.InitializationExpiresAt100ns;
    RtlCopyMemory(Status->LeaseId, g_YcpState.LeaseId, sizeof(Status->LeaseId));
    RtlCopyMemory(Status->ImageSha256, g_YcpState.ImageSha256, sizeof(Status->ImageSha256));
    RtlCopyMemory(Status->InstanceNonce, g_YcpState.InstanceNonce, sizeof(Status->InstanceNonce));
    if (g_YcpState.ImagePath.Buffer != NULL) {
        RtlCopyMemory(Status->ImagePath, g_YcpState.ImagePath.Buffer, g_YcpState.ImagePath.Length);
    }
    if (g_YcpState.ProtectedRoot.Buffer != NULL) {
        RtlCopyMemory(Status->ProtectedRoot, g_YcpState.ProtectedRoot.Buffer, g_YcpState.ProtectedRoot.Length);
    }
    if (g_YcpState.ProtectedDataRoot.Buffer != NULL) {
        RtlCopyMemory(Status->ProtectedDataRoot, g_YcpState.ProtectedDataRoot.Buffer, g_YcpState.ProtectedDataRoot.Length);
    }
    RtlCopyMemory(&Status->TrayIdentity, &g_YcpState.TrayIdentity, sizeof(Status->TrayIdentity));
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

// Provisioning values are written by the signed installer and never taken from an IOCTL.
static WCHAR g_YcpTrustedImageBuffer[YCP_MAX_PATH_CHARS];
static UNICODE_STRING g_YcpTrustedImage;
static WCHAR g_YcpTrustedDataRootBuffer[YCP_MAX_PATH_CHARS];
static UNICODE_STRING g_YcpTrustedDataRoot;
static const UCHAR g_YcpServiceSid[] = {
    0x01,0x06,0x00,0x00,0x00,0x00,0x00,0x05,0x50,0x00,0x00,0x00,
    0xca,0x29,0xbe,0x68,0x10,0x95,0x9d,0x61,0xa6,0x77,0xb3,0xba,
    0xf2,0x38,0x14,0xd7,0xfd,0xd7,0xa1,0x75
};

static NTSTATUS
YcpReadTrustedPath(
    _In_ HANDLE ParametersKey,
    _In_ PUNICODE_STRING ValueName,
    _Out_writes_bytes_(StorageBytes) PWCH Storage,
    _In_ ULONG StorageBytes,
    _Out_ PUNICODE_STRING Result
    )
{
    PKEY_VALUE_PARTIAL_INFORMATION value;
    ULONG length;
    ULONG dataOffset = (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
    ULONG returned = 0;
    UNICODE_STRING devicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
    NTSTATUS status;

    if (Storage == NULL || Result == NULL || StorageBytes == 0 ||
        (StorageBytes % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    length = dataOffset + StorageBytes;
    value = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, length, YCP_POOL_TAG);
    if (value == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = ZwQueryValueKey(ParametersKey, ValueName, KeyValuePartialInformation, value, length, &returned);
    if (NT_SUCCESS(status)) {
        if (returned < dataOffset || value->Type != REG_SZ ||
            value->DataLength < 2 * sizeof(WCHAR) || value->DataLength > StorageBytes ||
            value->DataLength > returned - dataOffset ||
            value->DataLength % sizeof(WCHAR) != 0) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            RtlZeroMemory(Storage, StorageBytes);
            RtlCopyMemory(Storage, value->Data, value->DataLength);
            status = YcpFixedString(Storage, (USHORT)(StorageBytes / sizeof(WCHAR)), Result);
            if (NT_SUCCESS(status) && (Result->Length + sizeof(WCHAR) != value->DataLength ||
                !RtlPrefixUnicodeString(&devicePrefix, Result, TRUE))) {
                status = STATUS_INVALID_PARAMETER;
            }
        }
    }
    ExFreePoolWithTag(value, YCP_POOL_TAG);
    return status;
}

static NTSTATUS
YcpLoadTrustedImage(_In_ PUNICODE_STRING RegistryPath)
{
    HANDLE serviceKey = NULL;
    HANDLE parametersKey = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING parameters = RTL_CONSTANT_STRING(L"Parameters");
    UNICODE_STRING imageName = RTL_CONSTANT_STRING(L"TrustedImagePath");
    UNICODE_STRING dataRootName = RTL_CONSTANT_STRING(L"TrustedDataRoot");
    NTSTATUS status;

    InitializeObjectAttributes(&attributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&serviceKey, KEY_READ, &attributes);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &parameters, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, serviceKey, NULL);
        status = ZwOpenKey(&parametersKey, KEY_QUERY_VALUE, &attributes);
    }
    if (NT_SUCCESS(status)) {
        status = YcpReadTrustedPath(
            parametersKey,
            &imageName,
            g_YcpTrustedImageBuffer,
            sizeof(g_YcpTrustedImageBuffer),
            &g_YcpTrustedImage);
    }
    if (NT_SUCCESS(status)) {
        status = YcpReadTrustedPath(
            parametersKey,
            &dataRootName,
            g_YcpTrustedDataRootBuffer,
            sizeof(g_YcpTrustedDataRootBuffer),
            &g_YcpTrustedDataRoot);
    }
    if (parametersKey != NULL) ZwClose(parametersKey);
    if (serviceKey != NULL) ZwClose(serviceKey);
    return status;
}

static BOOLEAN
YcpHasServiceIdentity(_In_ PEPROCESS Caller)
{
    PACCESS_TOKEN token;
    PTOKEN_GROUPS groups = NULL;
    PTOKEN_USER user = NULL;
    PULONG sessionId = NULL;
    BOOLEAN allowed = FALSE;
    ULONG index;
    static const UCHAR systemSid[] = { 1,1,0,0,0,0,0,5,18,0,0,0 };
    token = PsReferencePrimaryToken(Caller);
    if (token == NULL) return FALSE;
    if (NT_SUCCESS(SeQueryInformationToken(token, TokenSessionId, (PVOID *)&sessionId)) &&
        sessionId != NULL && *sessionId == 0 &&
        NT_SUCCESS(SeQueryInformationToken(token, TokenUser, (PVOID *)&user)) &&
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
    if (sessionId != NULL) ExFreePool(sessionId);
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
    _In_ const WCHAR *ProtectedDataRoot,
    _Out_ PUNICODE_STRING ImagePath,
    _Out_ PUNICODE_STRING RootPath,
    _Out_ PUNICODE_STRING DataRootPath
    )
{
    NTSTATUS status;
    UNICODE_STRING requestedImage;
    UNICODE_STRING requestedRoot;
    UNICODE_STRING requestedDataRoot;
    PUNICODE_STRING locatedImage = NULL;

    RtlZeroMemory(ImagePath, sizeof(*ImagePath));
    RtlZeroMemory(RootPath, sizeof(*RootPath));
    RtlZeroMemory(DataRootPath, sizeof(*DataRootPath));

    if (Caller == NULL || Identity == NULL || !YcpHasServiceIdentity(Caller) ||
        Identity->ProcessId != (ULONG)(ULONG_PTR)PsGetProcessId(Caller) ||
        Identity->SessionId != 0 ||
        Identity->CreateTime100ns != PsGetProcessCreateTimeQuadPart(Caller) ||
        YcpIsZeroBytes(Identity->InstanceNonce, sizeof(Identity->InstanceNonce)) ||
        YcpIsZeroBytes(Identity->ImageSha256, sizeof(Identity->ImageSha256))) {
        return STATUS_ACCESS_DENIED;
    }

    status = YcpFixedString(Identity->ImagePath, YCP_MAX_PATH_CHARS, &requestedImage);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = YcpFixedString(ProtectedDataRoot, YCP_MAX_PATH_CHARS, &requestedDataRoot);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!RtlEqualUnicodeString(&requestedDataRoot, &g_YcpTrustedDataRoot, TRUE)) {
        return STATUS_ACCESS_DENIED;
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
    if (NT_SUCCESS(status)) {
        status = YcpCopyString(&requestedDataRoot, DataRootPath);
    }
    if (locatedImage != NULL) {
        ExFreePool(locatedImage);
    }
    if (!NT_SUCCESS(status)) {
        YcpFreeString(ImagePath);
        YcpFreeString(RootPath);
        YcpFreeString(DataRootPath);
    }
    return status;
}

static NTSTATUS
YcpValidateTrayIdentity(
    _In_ const YCP_PROCESS_IDENTITY *Identity,
    _Out_ PEPROCESS *TrayProcess
    )
{
    PEPROCESS process = NULL;
    PUNICODE_STRING locatedImage = NULL;
    UNICODE_STRING requestedImage;
    NTSTATUS status;

    if (TrayProcess == NULL || Identity == NULL || Identity->ProcessId == 0 ||
        Identity->SessionId == 0 || Identity->CreateTime100ns <= 0 ||
        YcpIsZeroBytes(Identity->InstanceNonce, sizeof(Identity->InstanceNonce)) ||
        YcpIsZeroBytes(Identity->ImageSha256, sizeof(Identity->ImageSha256))) {
        return STATUS_INVALID_PARAMETER;
    }
    status = YcpFixedString(Identity->ImagePath, YCP_MAX_PATH_CHARS, &requestedImage);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Identity->ProcessId, &process);
    if (!NT_SUCCESS(status) || process == NULL) {
        return STATUS_NOT_FOUND;
    }
    if (PsGetProcessCreateTimeQuadPart(process) != Identity->CreateTime100ns ||
        PsGetProcessExitStatus(process) != STATUS_PENDING ||
        !YcpProcessSessionMatches(process, Identity->SessionId) ||
        !NT_SUCCESS(SeLocateProcessImageName(process, &locatedImage)) ||
        locatedImage == NULL) {
        if (locatedImage != NULL) ExFreePool(locatedImage);
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }
    if (!RtlEqualUnicodeString(&requestedImage, locatedImage, TRUE) ||
        !RtlEqualUnicodeString(&g_YcpTrustedImage, locatedImage, TRUE)) {
        if (locatedImage != NULL) ExFreePool(locatedImage);
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }
    if (locatedImage != NULL) ExFreePool(locatedImage);
    *TrayProcess = process;
    return STATUS_SUCCESS;
}

static NTSTATUS
YcpValidateCallerLocked(
    _In_ PEPROCESS Caller
    );

static NTSTATUS
YcpBeginInitialization(
    _In_ PEPROCESS Caller,
    _In_ const YCP_ACTIVATE_REQUEST *Request
    )
{
    NTSTATUS status;
    UNICODE_STRING imagePath;
    UNICODE_STRING rootPath;
    UNICODE_STRING dataRootPath;
    YCP_INITIALIZATION_COVERAGE coverage;

    RtlZeroMemory(&coverage, sizeof(coverage));

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (Request->InitializationManifestEntries == 0 ||
        Request->InitializationManifestEntries > YCP_MAX_INITIALIZATION_ENTRIES ||
        Request->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = YcpValidateIdentity(
        Caller,
        &Request->Identity,
        Request->ProtectedRoot,
        Request->ProtectedDataRoot,
        &imagePath,
        &rootPath,
        &dataRootPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = YcpAllocateInitializationCoverage(
        Request->InitializationManifestEntries,
        &coverage);
    if (!NT_SUCCESS(status)) {
        YcpFreeString(&imagePath);
        YcpFreeString(&rootPath);
        YcpFreeString(&dataRootPath);
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    if (g_YcpState.Unloading) {
        ExReleasePushLockExclusive(&g_YcpState.Lock);
        KeLeaveCriticalRegion();
        YcpFreeString(&imagePath);
        YcpFreeString(&rootPath);
        YcpFreeString(&dataRootPath);
        YcpFreeInitializationCoverage(&coverage);
        return STATUS_DEVICE_BUSY;
    }

    if (g_YcpState.TargetProcess != NULL) {
        if (g_YcpState.Initializing && !YcpInitializationValidLocked()) {
            // A timed-out or exited initialization is stale and can be
            // recovered by the next service instance. A stable Active target
            // remains untouched and is never replaced by a new Begin.
            YcpClearTargetLocked();
        } else if (PsGetProcessExitStatus(g_YcpState.TargetProcess) == STATUS_PENDING) {
            ExReleasePushLockExclusive(&g_YcpState.Lock);
            KeLeaveCriticalRegion();
            YcpFreeString(&imagePath);
            YcpFreeString(&rootPath);
            YcpFreeString(&dataRootPath);
            YcpFreeInitializationCoverage(&coverage);
            return STATUS_DEVICE_BUSY;
        } else {
            YcpClearTargetLocked();
        }
    }

    if (g_YcpState.InitializationGeneration == MAXULONGLONG) {
        ExReleasePushLockExclusive(&g_YcpState.Lock);
        KeLeaveCriticalRegion();
        YcpFreeString(&imagePath);
        YcpFreeString(&rootPath);
        YcpFreeString(&dataRootPath);
        YcpFreeInitializationCoverage(&coverage);
        return STATUS_INTEGER_OVERFLOW;
    }

    g_YcpState.TargetProcess = Caller;
    ObReferenceObject(Caller);
    g_YcpState.TargetPid = Request->Identity.ProcessId;
    g_YcpState.TargetCreateTime100ns = Request->Identity.CreateTime100ns;
    g_YcpState.ImagePath = imagePath;
    g_YcpState.ProtectedRoot = rootPath;
    g_YcpState.ProtectedDataRoot = dataRootPath;
    RtlCopyMemory(g_YcpState.ImageSha256, Request->Identity.ImageSha256, sizeof(g_YcpState.ImageSha256));
    RtlCopyMemory(g_YcpState.InstanceNonce, Request->Identity.InstanceNonce, sizeof(g_YcpState.InstanceNonce));
    g_YcpState.LeaseExpiresAt100ns = 0;
    RtlZeroMemory(g_YcpState.LeaseId, sizeof(g_YcpState.LeaseId));
    g_YcpState.Maintenance = FALSE;
    g_YcpState.UnloadPrepared = FALSE;
    g_YcpState.Active = FALSE;
    g_YcpState.Initializing = TRUE;
    ++g_YcpState.InitializationGeneration;
    g_YcpState.InitializationCoverage = coverage;
    RtlZeroMemory(&coverage, sizeof(coverage));
    g_YcpState.InitializationManifestEntries = Request->InitializationManifestEntries;
    {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        g_YcpState.InitializationExpiresAt100ns = now.QuadPart +
            ((LONGLONG)YCP_INITIALIZATION_TIMEOUT_SECONDS * 10000000LL);
    }
    g_YcpState.LastRequestId = Request->Header.RequestId;
    g_YcpState.LastStatus = STATUS_SUCCESS;
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

static NTSTATUS
YcpDeclareInitializationEntry(
    _In_ PEPROCESS Caller,
    _In_ const YCP_INITIALIZATION_ENTRY_REQUEST *Request
    )
{
    NTSTATUS status;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (Request->Reserved != 0 || Request->Flags != 0 ||
        YcpIsZeroBytes(Request->InstanceNonce, sizeof(Request->InstanceNonce))) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status)) {
        if (!YcpInitializationValidLocked() || g_YcpState.Active) {
            status = STATUS_INVALID_DEVICE_STATE;
        } else if (!RtlEqualMemory(g_YcpState.InstanceNonce, Request->InstanceNonce,
                                   sizeof(g_YcpState.InstanceNonce))) {
            status = STATUS_ACCESS_DENIED;
        } else if (!YcpInitializationCoverageDeclare(
                       &g_YcpState.InitializationCoverage,
                       Request->Identity.VolumeSerialNumber,
                       Request->Identity.FileIndex,
                       Request->Flags)) {
            status = STATUS_DEVICE_NOT_READY;
        } else {
            g_YcpState.LastRequestId = Request->Header.RequestId;
            g_YcpState.LastStatus = STATUS_SUCCESS;
        }
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
YcpCommitInitialization(
    _In_ PEPROCESS Caller,
    _In_ const YCP_INITIALIZE_COMMIT_REQUEST *Request
    )
{
    NTSTATUS status;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status) || Request->ExpectedEntries == 0 || Request->Reserved != 0 ||
        YcpIsZeroBytes(Request->InstanceNonce, sizeof(Request->InstanceNonce))) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status)) {
        if (!g_YcpState.Initializing || g_YcpState.Active) {
            status = STATUS_INVALID_DEVICE_STATE;
        } else if (!RtlEqualMemory(g_YcpState.InstanceNonce, Request->InstanceNonce,
                                   sizeof(g_YcpState.InstanceNonce))) {
            status = STATUS_ACCESS_DENIED;
        } else if (!YcpInitializationValidLocked()) {
            status = STATUS_TIMEOUT;
        } else if (!YcpInitializationCoverageCanCommit(
                       &g_YcpState.InitializationCoverage,
                       Request->ExpectedEntries)) {
            status = STATUS_DEVICE_NOT_READY;
        } else if (g_YcpState.LastRequestId == Request->Header.RequestId) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            g_YcpState.Initializing = FALSE;
            g_YcpState.InitializationExpiresAt100ns = 0;
            g_YcpState.Active = TRUE;
            g_YcpState.LastRequestId = Request->Header.RequestId;
            g_YcpState.LastStatus = STATUS_SUCCESS;
        }
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
YcpAbortInitialization(
    _In_ PEPROCESS Caller,
    _In_ const YCP_INITIALIZE_ABORT_REQUEST *Request
    )
{
    NTSTATUS status;
    ULONGLONG requestId = Request->Header.RequestId;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status) || YcpIsZeroBytes(Request->InstanceNonce, sizeof(Request->InstanceNonce))) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status) && !g_YcpState.Initializing) {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    if (NT_SUCCESS(status) && !RtlEqualMemory(g_YcpState.InstanceNonce, Request->InstanceNonce,
                                               sizeof(g_YcpState.InstanceNonce))) {
        status = STATUS_ACCESS_DENIED;
    }
    if (NT_SUCCESS(status)) {
        YcpClearTargetLocked();
        g_YcpState.LastRequestId = requestId;
        g_YcpState.LastStatus = STATUS_SUCCESS;
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
YcpValidateCallerLocked(
    _In_ PEPROCESS Caller
    )
{
    return !g_YcpState.Unloading && YcpTargetMatchesLocked(Caller) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

static NTSTATUS
YcpRegisterTray(
    _In_ PEPROCESS Caller,
    _In_ const YCP_TRAY_REQUEST *Request
    )
{
    NTSTATUS status;
    PEPROCESS trayProcess = NULL;

    status = YcpValidateHeader(&Request->Header, sizeof(*Request));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = YcpValidateTrayIdentity(&Request->Identity, &trayProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    status = YcpValidateCallerLocked(Caller);
    if (NT_SUCCESS(status) && !g_YcpState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    }
    if (NT_SUCCESS(status) && YcpLeaseValidLocked()) {
        status = STATUS_DEVICE_BUSY;
    }
    if (NT_SUCCESS(status) && trayProcess == g_YcpState.TargetProcess) {
        status = STATUS_INVALID_PARAMETER;
    }
    if (NT_SUCCESS(status) && g_YcpState.TrayProcess != NULL) {
        if (YcpIdentityEquals(&g_YcpState.TrayIdentity, &Request->Identity)) {
            // Repeated registration of the same live identity is idempotent.
            ObDereferenceObject(trayProcess);
            trayProcess = NULL;
        } else if (PsGetProcessExitStatus(g_YcpState.TrayProcess) == STATUS_PENDING) {
            status = STATUS_DEVICE_BUSY;
        } else {
            YcpClearTrayLocked();
        }
    }
    if (NT_SUCCESS(status) && trayProcess != NULL) {
        g_YcpState.TrayProcess = trayProcess;
        RtlCopyMemory(&g_YcpState.TrayIdentity, &Request->Identity, sizeof(g_YcpState.TrayIdentity));
        trayProcess = NULL;
    }
    if (NT_SUCCESS(status)) {
        g_YcpState.LastRequestId = Request->Header.RequestId;
        g_YcpState.LastStatus = STATUS_SUCCESS;
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    if (trayProcess != NULL) ObDereferenceObject(trayProcess);
    return status;
}

static NTSTATUS
YcpUnregisterTray(
    _In_ PEPROCESS Caller,
    _In_ const YCP_TRAY_REQUEST *Request
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
    if (NT_SUCCESS(status) && !g_YcpState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    }
    if (NT_SUCCESS(status) && g_YcpState.TrayProcess != NULL &&
        !YcpIdentityEquals(&g_YcpState.TrayIdentity, &Request->Identity)) {
        status = STATUS_ACCESS_DENIED;
    }
    if (NT_SUCCESS(status)) {
        YcpClearTrayLocked();
        g_YcpState.LastRequestId = Request->Header.RequestId;
        g_YcpState.LastStatus = STATUS_SUCCESS;
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return status;
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
    if (NT_SUCCESS(status) && !g_YcpState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    }
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
    if (NT_SUCCESS(status) && !g_YcpState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    }
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
    if (NT_SUCCESS(status) && !g_YcpState.Active) {
        status = STATUS_DEVICE_NOT_READY;
    }
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
    if ((g_YcpState.Active || g_YcpState.Initializing) && !YcpTargetMatchesLocked(Caller)) {
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
    active = g_YcpState.Active && !g_YcpState.Unloading;
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return active;
}

BOOLEAN
YcpProtectionIsInitializing(
    VOID
    )
{
    BOOLEAN initializing;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    initializing = YcpInitializationValidLocked();
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return initializing;
}

VOID
YcpRecordInitializationStream(
    _In_ const YCP_INITIALIZATION_OBSERVATION_CONTEXT *Snapshot,
    _In_opt_ const YCP_INITIALIZATION_FILE_IDENTITY *Identity,
    _In_ ULONG Flags,
    _In_ BOOLEAN Marked
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_YcpState.Lock);
    if (Snapshot != NULL && Snapshot->OwnerProcess != NULL &&
        YcpInitializationValidLocked() &&
        Snapshot->OwnerProcess == g_YcpState.TargetProcess &&
        Snapshot->Generation == g_YcpState.InitializationGeneration &&
        RtlEqualMemory(
            Snapshot->InstanceNonce,
            g_YcpState.InstanceNonce,
            sizeof(Snapshot->InstanceNonce))) {
        YcpInitializationCoverageObserve(
            &g_YcpState.InitializationCoverage,
            Identity == NULL ? 0 : Identity->VolumeSerialNumber,
            Identity == NULL ? 0 : Identity->FileIndex,
            Flags,
            Marked ? 1 : 0);
    }
    ExReleasePushLockExclusive(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
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
    protect = g_YcpState.Active && !YcpLeaseValidLocked() &&
        (YcpTargetMatchesLocked(ProcessObject) || YcpTrayTargetMatchesLocked(ProcessObject));
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
    protect = (g_YcpState.Active || YcpInitializationValidLocked()) && !g_YcpState.Unloading &&
        ((g_YcpState.ProtectedRoot.Buffer != NULL &&
          YcpPathHasBoundaryPrefix(&g_YcpState.ProtectedRoot, NormalizedName)) ||
         (g_YcpState.ProtectedDataRoot.Buffer != NULL &&
          YcpPathHasBoundaryPrefix(&g_YcpState.ProtectedDataRoot, NormalizedName)));
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return protect;
}

BOOLEAN
YcpShouldProtectAncestor(_In_ PUNICODE_STRING NormalizedName)
{
    BOOLEAN protect;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    protect = (g_YcpState.Active || YcpInitializationValidLocked()) && !g_YcpState.Unloading &&
        ((g_YcpState.ProtectedRoot.Buffer != NULL &&
          YcpPathIsStrictAncestor(NormalizedName, &g_YcpState.ProtectedRoot)) ||
         (g_YcpState.ProtectedDataRoot.Buffer != NULL &&
          YcpPathIsStrictAncestor(NormalizedName, &g_YcpState.ProtectedDataRoot)));
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return protect;
}

BOOLEAN
YcpIsTrustedWriter(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    PEPROCESS process;
    BOOLEAN allowed = FALSE;

    if (Data == NULL) return FALSE;
    process = FltGetRequestorProcess(Data);
    if (process == NULL) return FALSE;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_YcpState.Lock);
    allowed = (g_YcpState.Active || YcpInitializationValidLocked()) &&
        !g_YcpState.Unloading && YcpTargetMatchesLocked(process);
    ExReleasePushLockShared(&g_YcpState.Lock);
    KeLeaveCriticalRegion();
    return allowed;
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
    case IOCTL_YCP_BEGIN_INITIALIZE:
        if (inputLength != sizeof(YCP_ACTIVATE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpBeginInitialization(caller, (const YCP_ACTIVATE_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_COMMIT_INITIALIZE:
        if (inputLength != sizeof(YCP_INITIALIZE_COMMIT_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpCommitInitialization(
                caller,
                (const YCP_INITIALIZE_COMMIT_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_ABORT_INITIALIZE:
        if (inputLength != sizeof(YCP_INITIALIZE_ABORT_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpAbortInitialization(
                caller,
                (const YCP_INITIALIZE_ABORT_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_DECLARE_INITIALIZATION_ENTRY:
        if (inputLength != sizeof(YCP_INITIALIZATION_ENTRY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpDeclareInitializationEntry(
                caller,
                (const YCP_INITIALIZATION_ENTRY_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_REGISTER_TRAY:
        if (inputLength != sizeof(YCP_TRAY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpRegisterTray(caller, (const YCP_TRAY_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_UNREGISTER_TRAY:
        if (inputLength != sizeof(YCP_TRAY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpUnregisterTray(caller, (const YCP_TRAY_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_ENTER_MAINTENANCE:
        if (inputLength != sizeof(YCP_MAINTENANCE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpEnterMaintenance(caller, (const YCP_MAINTENANCE_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_EXIT_MAINTENANCE:
        if (inputLength != sizeof(YCP_MAINTENANCE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpExitMaintenance(caller, (const YCP_MAINTENANCE_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_PREPARE_UNLOAD:
        if (inputLength != sizeof(YCP_UNLOAD_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = YcpPrepareUnload(caller, (const YCP_UNLOAD_REQUEST *)buffer);
        }
        break;

    case IOCTL_YCP_QUERY_STATUS:
        if (inputLength != 0 || outputLength != sizeof(YCP_STATUS)) {
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
    allowed = !g_YcpState.Unloading && g_YcpState.OpenFileObjects == 0 &&
        ((!g_YcpState.Active && (!g_YcpState.Initializing || !YcpInitializationValidLocked())) ||
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
