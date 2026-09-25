using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using optiSCAN.Views;

namespace optiSCAN.Coordinators;

/// <summary>Données pour rafraîchir la carte protection / recommandations de l'accueil.</summary>
public sealed record OverviewRefreshContext(
    IOverviewPanel Panel,
    bool ClamInstalled,
    int YaraRulesCount,
    bool YaraAvailable,
    IReadOnlyList<CleanSession> CleanHistory,
    IReadOnlyList<ScanSession> ScanHistory,
    DateTime? LastFreshclamUpdate,
    bool RealTimeProtectionEnabled,
    bool RealTimeProtectionRunning,
    bool SignatureAutoUpdateEnabled,
    ISecurityPostureService SecurityPosture,
    PlatformProtectionStatusReport? PlatformStatus = null);

/// <summary>Données pour rafraîchir les libellés de versions ClamAV / YARA.</summary>
public sealed record SignaturesRefreshContext(
    SignatureStatusService SignatureStatus,
    IOverviewPanel? OverviewPanel,
    IAntivirusSignaturesPanel? AntivirusPanel,
    ScanViewModel? ViewModel,
    Action? AfterSignaturesRefreshed);

/// <summary>Rafraîchissement vue d'ensemble et signatures sans couplage XAML par nom.</summary>
public static class OverviewRefreshCoordinator
{
    public static void RefreshProtectionAndRecommendations(OverviewRefreshContext ctx)
    {
        bool protectedOk = ctx.ClamInstalled && (!ctx.YaraAvailable || ctx.YaraRulesCount > 0);
        ctx.Panel.UpdateProtectionHeadline(protectedOk);

        var rec = OverviewRecommendationsBuilder.Build(new OverviewRecommendationsBuilder.Context
        {
            ClamInstalled = ctx.ClamInstalled,
            LastFreshclamUpdate = ctx.LastFreshclamUpdate,
            LastCleanAt = ctx.CleanHistory.Count > 0 ? ctx.CleanHistory[0].StartedAt : null,
        });

        ctx.Panel.UpdateRecommendations(
            rec.HygieneLine,
            rec.HygieneSeverity,
            rec.ShowSigUpdateLink,
            rec.FixAction);

        var lastScan = ctx.ScanHistory.Count > 0 ? ctx.ScanHistory[0].StartedAt : (DateTime?)null;
        var posture = ctx.SecurityPosture.Evaluate(new SecurityPostureContext
        {
            ClamInstalled = ctx.ClamInstalled,
            YaraAvailable = ctx.YaraAvailable,
            YaraRulesCount = ctx.YaraRulesCount,
            RealTimeProtectionEnabled = ctx.RealTimeProtectionEnabled,
            RealTimeProtectionRunning = ctx.RealTimeProtectionRunning,
            LastScanAt = lastScan,
            SignatureAutoUpdateEnabled = ctx.SignatureAutoUpdateEnabled,
        });
        ctx.Panel.UpdateSecurityPosture(posture);
        // PlatformStatus est calculé en arrière-plan (fltmc + ping pipe) ; repli synchrone si absent.
        ctx.Panel.UpdatePlatformProtectionStatus(ctx.PlatformStatus ?? PlatformProtectionStatusService.Evaluate());
    }

    public static async Task RefreshSignaturesAsync(SignaturesRefreshContext ctx, bool forceRefresh = false)
    {
        var snapshot = await ctx.SignatureStatus.GetSnapshotAsync(forceRefresh).ConfigureAwait(false);

        ctx.AntivirusPanel?.UpdateSignaturesPanel(
            snapshot.YaraPackVersion,
            snapshot.YaraLastUpdateDisplay,
            snapshot.ClamDatabaseVersion,
            snapshot.ClamLastUpdateDisplay);
        ctx.OverviewPanel?.UpdateSignaturesSummary(
            snapshot.YaraPackVersion,
            snapshot.YaraLastUpdateDisplay,
            snapshot.ClamDatabaseVersion,
            snapshot.ClamLastUpdateDisplay);

        if (ctx.ViewModel != null)
            snapshot.ApplyToScanViewModel(ctx.ViewModel);

        ctx.AfterSignaturesRefreshed?.Invoke();
    }
}

/// <summary>Construit <see cref="OverviewRefreshContext"/> depuis le container applicatif.</summary>
public static class OverviewRefreshContextBuilder
{
    public static OverviewRefreshContext FromContainer(IOverviewPanel panel, ServiceContainer container) =>
        FromContainer(panel, container, scanHistory: null, cleanHistory: null, includePlatformStatus: false);

    /// <summary>
    /// Variante appelable hors thread UI : les historiques (listes non thread-safe) doivent être
    /// capturés au préalable sur le thread UI ; le statut plateforme (lent) est évalué ici.
    /// </summary>
    public static OverviewRefreshContext FromContainer(
        IOverviewPanel panel,
        ServiceContainer container,
        IReadOnlyList<ScanSession>? scanHistory,
        IReadOnlyList<CleanSession>? cleanHistory,
        bool includePlatformStatus)
    {
        return new OverviewRefreshContext(
            panel,
            ClamInstalled: container.ClamAv.IsClamAvInstalled(),
            YaraRulesCount: container.Yara.RulesCount,
            YaraAvailable: container.Yara.IsAvailable,
            CleanHistory: cleanHistory ?? container.Logger.GetCleanHistory(),
            ScanHistory: scanHistory ?? container.Logger.GetHistory(),
            LastFreshclamUpdate: container.FreshclamUpdater.GetLastSignatureUpdateTime(),
            RealTimeProtectionEnabled: container.ExclusionSettingsAccessor.Current.RealTimeEnabled,
            RealTimeProtectionRunning: container.RealTimeProtection.IsEnabled
                || PlatformProtectionBootstrap.IsRemoteProtectionActive(),
            SignatureAutoUpdateEnabled: container.UserPreferencesAccessor.Current.SignatureAutoUpdateEnabled,
            SecurityPosture: container.SecurityPosture,
            PlatformStatus: includePlatformStatus ? PlatformProtectionStatusService.Evaluate() : null);
    }
}
