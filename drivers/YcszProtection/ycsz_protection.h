#pragma once

#include <ntifs.h>
#include <fltKernel.h>
#include "ycsz_protection_protocol.h"
#include "ycsz_initialization_coverage.h"

#define YCP_POOL_TAG 'pCYZ'

BOOLEAN
YcpShouldProtectProcess(
    _In_ PEPROCESS ProcessObject
    );

BOOLEAN
YcpShouldProtectFile(
    _In_ PUNICODE_STRING NormalizedName
    );

BOOLEAN
YcpIsTrustedWriter(
    _In_ PFLT_CALLBACK_DATA Data
    );

BOOLEAN
YcpProtectionIsActive(
    VOID
    );

BOOLEAN
YcpProtectionIsInitializing(
    VOID
    );

typedef struct _YCP_INITIALIZATION_OBSERVATION_CONTEXT {
    PEPROCESS OwnerProcess;
    ULONGLONG Generation;
    UCHAR InstanceNonce[16];
} YCP_INITIALIZATION_OBSERVATION_CONTEXT, *PYCP_INITIALIZATION_OBSERVATION_CONTEXT;

BOOLEAN
YcpCaptureInitializationSnapshot(
    _In_ PEPROCESS Requestor,
    _Out_ PYCP_INITIALIZATION_OBSERVATION_CONTEXT Snapshot
    );

VOID
YcpReleaseInitializationSnapshot(
    _Inout_ PYCP_INITIALIZATION_OBSERVATION_CONTEXT Snapshot
    );

VOID
YcpRecordInitializationStream(
    _In_ const YCP_INITIALIZATION_OBSERVATION_CONTEXT *Snapshot,
    _In_opt_ const YCP_INITIALIZATION_FILE_IDENTITY *Identity,
    _In_ ULONG Flags,
    _In_ BOOLEAN Marked
    );

BOOLEAN
YcpMaintenanceIsActive(
    VOID
    );

NTSTATUS
YcpCompleteIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    );

extern const FLT_REGISTRATION g_YcpFilterRegistration;

NTSTATUS YcpFilterUnloadAuthorized(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

BOOLEAN YcpShouldProtectAncestor(_In_ PUNICODE_STRING NormalizedName);
