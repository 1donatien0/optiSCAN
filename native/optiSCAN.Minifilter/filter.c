/*
 * optiSCAN Minifilter v1 — squelette WDK
 *
 * Compilation : Windows Driver Kit 10 + certificat EV (production) ou test signing (dev).
 * Ce fichier documente l'interface minimale ; le .sys n'est pas produit par la CI dotnet.
 *
 * Étapes :
 *   1. Créer un projet Empty WDM Driver dans Visual Studio (filtre activité)
 *   2. Lier fltMgr.lib, inclure fltKernel.h
 *   3. Signer et copier vers %SystemRoot%\System32\drivers\
 *   4. fltmc load optiSCANMinifilter
 */

#ifdef OPTISCAN_MINIFILTER_BUILD

#include <fltKernel.h>

PFLT_FILTER g_OptiscanFilter = NULL;

NTSTATUS OptiscanUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

/* Globales : le gestionnaire de filtres garde des références vers ces tables. */
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                  /* Flags */
    NULL,               /* ContextRegistration */
    g_Callbacks,        /* OperationRegistration */
    OptiscanUnload,     /* FilterUnloadCallback */
    NULL,               /* InstanceSetupCallback */
    NULL,               /* InstanceQueryTeardownCallback */
    NULL,               /* InstanceTeardownStartCallback */
    NULL,               /* InstanceTeardownCompleteCallback */
    NULL,               /* GenerateFileNameCallback */
    NULL,               /* NormalizeNameComponentCallback */
    NULL,               /* NormalizeContextCleanupCallback */
};

NTSTATUS OptiscanUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (g_OptiscanFilter != NULL)
    {
        FltUnregisterFilter(g_OptiscanFilter);
        g_OptiscanFilter = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_Registration, &g_OptiscanFilter);
    if (!NT_SUCCESS(status))
        return status;

    /* Sans FltStartFiltering, le filtre est enregistré mais ne reçoit aucune opération. */
    status = FltStartFiltering(g_OptiscanFilter);
    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(g_OptiscanFilter);
        g_OptiscanFilter = NULL;
    }
    return status;
}

#endif /* OPTISCAN_MINIFILTER_BUILD */
