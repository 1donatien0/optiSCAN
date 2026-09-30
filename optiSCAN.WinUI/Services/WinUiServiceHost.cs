using optiSCAN.Coordinators;
using optiSCAN.Localization;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using optiSCAN.Views;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Services;

/// <summary>Point d'entrée services optiSCAN pour le shell WinUI 3 (modèle optiCombat).</summary>
public sealed class WinUiServiceHost
{
    public static WinUiServiceHost Instance { get; } = new();

    public ServiceContainer Container { get; }

    // Les VM sont créées par InitializeUi avec le vrai thread UI et le vrai service de confirmation.
    // Auparavant des instances « provisoires » étaient construites ici puis remplacées : une seconde
    // AntivirusViewModel restait abonnée aux mises à jour de signatures (travail en double, jamais libérée)
    // et les confirmations de ces instances étaient toujours refusées.
    private AntivirusViewModel? _antivirus;
    private CleanViewModel? _clean;
    private OptionsViewModel? _options;

    public AntivirusViewModel Antivirus =>
        _antivirus ??= new AntivirusViewModel(Container, DeclineUserConfirmService.Instance, SyncUiThreadScheduler.Instance);

    public HistoryViewModel History { get; }

    public CleanViewModel Clean => _clean ??= new CleanViewModel(Container);

    public OptionsViewModel Options => _options ??= new OptionsViewModel(Container);

    private WinUiServiceHost()
    {
        LocalizationService.Initialize();
        Container = ServiceContainer.Default;
        History = new HistoryViewModel(Container);
    }

    public void InitializeUi(AntivirusViewModel antivirusViewModel, IUiThreadScheduler ui, IUserConfirmService? confirm = null, Action<bool>? applyTheme = null)
    {
        _antivirus = antivirusViewModel;
        _clean = new CleanViewModel(Container, ui, confirm);
        _options = new OptionsViewModel(Container, applyTheme, ui, confirm);
        Container.ThreatLookup = path => Antivirus.Threats.FirstOrDefault(t =>
            string.Equals(t.FilePath, path, StringComparison.OrdinalIgnoreCase));
    }

    public void RefreshOverview(IOverviewPanel panel)
    {
        OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(
            OverviewRefreshContextBuilder.FromContainer(panel, Container));

        var sessions = Container.Logger.GetHistory();
        panel.UpdateProtectionStatistics(sessions);

        var last = sessions.Count == 0
            ? null
            : sessions.OrderByDescending(s => s.StartedAt).First();
        panel.UpdateLastScanSummary(last);

        panel.UpdateAntivirusCardStatus(
            Container.ClamAv.IsClamAvInstalled(),
            Container.Yara.RulesCount,
            Container.ClamActiveEngine);
    }

    public async Task RefreshOverviewAsync(IOverviewPanel panel, bool forceSignatures = false)
    {
        RefreshOverview(panel);
        await OverviewRefreshCoordinator.RefreshSignaturesAsync(
            new SignaturesRefreshContext(
                Container.SignatureStatus,
                panel,
                AntivirusPanel: null,
                ApplySnapshot: snapshot => snapshot.ApplyTo(Antivirus),
                AfterSignaturesRefreshed: () => RefreshOverview(panel)),
            forceSignatures).ConfigureAwait(true);
    }

    public async Task RefreshAntivirusAsync(IAntivirusSignaturesPanel? panel = null, bool forceSignatures = false)
    {
        Antivirus.RefreshProtectionStatus();
        Antivirus.RefreshQuarantineList();
        await OverviewRefreshCoordinator.RefreshSignaturesAsync(
            new SignaturesRefreshContext(
                Container.SignatureStatus,
                panel as IOverviewPanel,
                panel,
                ApplySnapshot: snapshot => snapshot.ApplyTo(Antivirus),
                AfterSignaturesRefreshed: () => Antivirus.RefreshProtectionStatus()),
            forceSignatures).ConfigureAwait(true);
    }
}
