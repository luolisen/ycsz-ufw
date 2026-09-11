#pragma once

#include <ntifs.h>
#include <fltKernel.h>
#include "ycsz_protection_protocol.h"

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
