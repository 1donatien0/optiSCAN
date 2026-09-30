using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.Views;
using optiSCAN.WinUI.Services;
using System.Diagnostics;
using System.Globalization;

namespace optiSCAN.WinUI.Views;

public sealed partial class OverviewPage : UserControl, IOverviewPanel
{
    private bool? _isNarrowLayout;

    private readonly IUserConfirmService _confirm;
    private bool _fixRunning;

    public OverviewPage(IUserConfirmService? confirm = null)
    {
        _confirm = confirm ?? DeclineUserConfirmService.Instance;
        InitializeComponent();
        BuildScanFlyout();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplyStaticLabels();
        WinUiThemeManager.ThemeChanged += OnThemeChanged;
        ApplyAdaptiveLayout(ActualWidth);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e) =>
        WinUiThemeManager.ThemeChanged -= OnThemeChanged;

    private void OnThemeChanged(object? sender, bool _)
    {
        RunOnUi(() =>
        {
            ClearDynamicForegrounds();
        });
    }

    private void Page_SizeChanged(object sender, SizeChangedEventArgs e) =>
        ApplyAdaptiveLayout(e.NewSize.Width);

    private void ApplyAdaptiveLayout(double width)
    {
        bool narrow = width < 720;
        // Ne reconstruire la grille que lorsque le mode change (pas à chaque pixel de redimensionnement).
        if (_isNarrowLayout == narrow)
            return;
        _isNarrowLayout = narrow;

        ActionGrid.ColumnDefinitions.Clear();
        ActionGrid.RowDefinitions.Clear();
        BottomCardsGrid.ColumnDefinitions.Clear();
        BottomCardsGrid.RowDefinitions.Clear();

        HeroBrandPanel.Visibility = narrow ? Visibility.Collapsed : Visibility.Visible;

        if (narrow)
        {
            ActionGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ActionGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ActionGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            ActionGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetColumn(ActionCleanBtn, 0);
            Grid.SetRow(ActionCleanBtn, 0);
            Grid.SetColumn(ActionScanBtn, 1);
            Grid.SetRow(ActionScanBtn, 0);
            Grid.SetColumn(ActionHistoryBtn, 0);
            Grid.SetRow(ActionHistoryBtn, 1);
            Grid.SetColumn(ActionUpdateBtn, 1);
            Grid.SetRow(ActionUpdateBtn, 1);

            BottomCardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            BottomCardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            BottomCardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            BottomCardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetColumn(LastScanCard, 0);
            Grid.SetRow(LastScanCard, 0);
            Grid.SetColumn(StatsCard, 0);
            Grid.SetRow(StatsCard, 1);
            Grid.SetColumn(SignaturesCard, 0);
            Grid.SetRow(SignaturesCard, 2);
        }
        else
        {
            for (int i = 0; i < 4; i++)
                ActionGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Grid.SetRow(ActionCleanBtn, 0);
            Grid.SetRow(ActionScanBtn, 0);
            Grid.SetRow(ActionHistoryBtn, 0);
            Grid.SetRow(ActionUpdateBtn, 0);
            Grid.SetColumn(ActionCleanBtn, 0);
            Grid.SetColumn(ActionScanBtn, 1);
            Grid.SetColumn(ActionHistoryBtn, 2);
            Grid.SetColumn(ActionUpdateBtn, 3);

            BottomCardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4, GridUnitType.Star) });
            BottomCardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4, GridUnitType.Star) });
            BottomCardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });
            BottomCardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(LastScanCard, 0);
            Grid.SetRow(StatsCard, 0);
            Grid.SetRow(SignaturesCard, 0);
            Grid.SetColumn(LastScanCard, 0);
            Grid.SetColumn(StatsCard, 1);
            Grid.SetColumn(SignaturesCard, 2);
        }
    }

    private void ApplyStaticLabels()
    {
        HeroLastScanLabel.Text = LocalizationService.GetString("Overview_LastScan");
        PostureSectionTitle.Text = LocalizationService.GetString("Posture_Title");
        LastScanSectionTitle.Text = LocalizationService.GetString("Overview_LastScan");
        StatsSectionTitle.Text = LocalizationService.GetString("Overview_StatsTitle");
        SignaturesSectionTitle.Text = LocalizationService.GetString("Overview_SignaturesSection");
        ActionCleanTitle.Text = LocalizationService.GetString("Overview_CleanTitle");
        ActionCleanSub.Text = LocalizationService.GetString("Overview_CleanSub");
        ActionScanTitle.Text = LocalizationService.GetString("Overview_ScanTitle");
        ActionScanSub.Text = LocalizationService.GetString("Overview_ScanSub");
        ActionHistoryTitle.Text = LocalizationService.GetString("Overview_HistoryTitle");
        ActionHistorySub.Text = LocalizationService.GetString("Overview_HistorySub");
        ActionUpdateTitle.Text = LocalizationService.GetString("Overview_UpdateTitle");
        ActionUpdateSub.Text = LocalizationService.GetString("Overview_UpdateSub");
        ElevationBannerText.Text = LocalizationService.GetString("Overview_PartialScanBanner");
        RunAsAdminButton.Content = LocalizationService.GetString("Overview_RunAsAdmin");
    }

    public void ApplyElevationBanner()
    {
        ElevationBanner.Visibility = ElevationHelper.IsRunningElevated()
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void RunAsAdmin_Click(object sender, RoutedEventArgs e)
    {
        // Passe par la fenêtre principale : fermeture propre + argument « --restart » pour que
        // l'instance élevée attende la libération du mutex (sinon elle se fermait aussitôt).
        if (App.MainWindowInstance is { } window)
            window.RestartElevated();
        else if (ElevationHelper.RelaunchElevated(App.RestartArgument))
            Application.Current.Exit();
    }

    private void ActionClean_Click(object sender, RoutedEventArgs e) =>
        WinUiServiceHost.Instance.Container.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Clean);

    /// <summary>Menu de la tuile Analyser : analyse rapide, complète ou choix manuel.</summary>
    private void BuildScanFlyout()
    {
        var flyout = new MenuFlyout();

        var quick = new MenuFlyoutItem
        {
            Text = LocalizationService.GetString("Av_Quick"),
            Icon = new FontIcon { Glyph = "\uE945" },
        };
        quick.Click += (_, _) => ServiceContainer.UiEvents.RequestScan(ScanType.QuickScan);

        var full = new MenuFlyoutItem
        {
            Text = LocalizationService.GetString("Av_Full"),
            Icon = new FontIcon { Glyph = "\uE721" },
        };
        full.Click += (_, _) => ServiceContainer.UiEvents.RequestScan(ScanType.FullScan);

        var custom = new MenuFlyoutItem
        {
            Text = LocalizationService.GetString("Overview_ScanTitle") + "…",
            Icon = new FontIcon { Glyph = "\uE8B7" },
        };
        custom.Click += (_, _) =>
        {
            WinUiServiceHost.Instance.Container.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
            ServiceContainer.UiEvents.RequestFocusAntivirusScanTab();
        };

        flyout.Items.Add(quick);
        flyout.Items.Add(full);
        flyout.Items.Add(new MenuFlyoutSeparator());
        flyout.Items.Add(custom);
        ActionScanBtn.Flyout = flyout;
    }

    private void ActionHistory_Click(object sender, RoutedEventArgs e) =>
        WinUiServiceHost.Instance.Container.Navigation?.NavigateTo(OptiscanStrings.PanelIds.History);

    private void ActionUpdateSig_Click(object sender, RoutedEventArgs e)
    {
        WinUiServiceHost.Instance.Container.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
        ServiceContainer.UiEvents.RequestFocusAntivirusSignaturesTab();
        ServiceContainer.UiEvents.TriggerSignatureUpdate();
    }

    private void ClearDynamicForegrounds()
    {
        ProtectionHeadline?.ClearValue(TextBlock.ForegroundProperty);
        AntivirusCardText?.ClearValue(TextBlock.ForegroundProperty);
    }

    private void RunOnUi(Action action) => DispatcherQueue.TryEnqueue(() => action());

    /// <summary>Couleur de texte suivant le thème (cf. <see cref="ThemeBrush"/>) pour les éléments créés par code.</summary>
    private static TextBlock Themed(TextBlock block, string brushKey)
    {
        ThemeBrush.SetForegroundKey(block, brushKey);
        return block;
    }

    public void UpdateProtectionHeadline(bool isProtected, string? headline = null)
    {
        RunOnUi(() =>
        {
            ProtectionHeadline.Text = string.IsNullOrWhiteSpace(headline)
                ? (isProtected
                    ? LocalizationService.GetString("Overview_Protected")
                    : LocalizationService.GetString("Overview_ProtectionIncomplete"))
                : headline;
            ProtectionSubtitle.Text = isProtected
                ? LocalizationService.GetString("Overview_ProtectedSub")
                : LocalizationService.GetString("Overview_PartialScanBanner");
            ProtectionSubtitle.Visibility = isProtected ? Visibility.Collapsed : Visibility.Visible;
        });
    }

    public void UpdateRecommendations(string hygieneLine, int hygieneSeverity, bool showSigUpdateLink = false)
    {
        RunOnUi(() =>
        {
            HygieneRecommendation.Text = hygieneLine;
            ThemeBrush.SetForegroundKey(HygieneRecommendation, hygieneSeverity switch
            {
                0 or 2 => "AccentBrush",
                1 => "WarningBrush",
                _ => "InfoBrush",
            });

            if (showSigUpdateLink)
            {
                SigUpdateLink.Content = LocalizationService.GetString("Rec_SigStaleAction");
                SigUpdateLink.Visibility = Visibility.Visible;
            }
            else
            {
                SigUpdateLink.Visibility = Visibility.Collapsed;
            }
        });
    }

    public void UpdateSecurityPosture(SecurityPostureReport report)
    {
        RunOnUi(() =>
        {
            SecurityScoreLine.Text = LocalizationService.Format("Export_Pdf_Score", report.Score);
            PostureIssuesPanel.Children.Clear();

            var failed = report.Checks.Where(c => !c.Passed).Take(4).ToList();
            if (failed.Count == 0)
            {
                PostureIssuesPanel.Children.Add(Themed(new TextBlock
                {
                    Text = LocalizationService.GetString("Posture_AllGood"),
                    TextWrapping = TextWrapping.WrapWholeWords,
                }, "SuccessGreen"));
                return;
            }

            foreach (var check in failed)
            {
                var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
                row.Children.Add(Themed(new TextBlock
                {
                    Text = "• " + check.Title,
                    TextWrapping = TextWrapping.WrapWholeWords,
                    VerticalAlignment = VerticalAlignment.Center,
                }, "TextMutedBrush"));

                if (!PostureFixService.CanAutoFix(check.Id) && !string.IsNullOrWhiteSpace(check.FixUri))
                {
                    var fixUri = check.FixUri;
                    var fix = new HyperlinkButton
                    {
                        Content = LocalizationService.GetString("Posture_Fix"),
                        Padding = new Thickness(0),
                        VerticalAlignment = VerticalAlignment.Center,
                    };
                    fix.Click += (_, _) => InvokePostureFix(fixUri);
                    row.Children.Add(fix);
                }
                else if (PostureFixService.CanAutoFix(check.Id))
                {
                    row.Children.Add(BuildAutoFixButton(check.Id));
                }

                PostureIssuesPanel.Children.Add(row);
            }
        });
    }

    public void UpdatePlatformProtectionStatus(PlatformProtectionStatusReport report)
    {
        RunOnUi(() =>
        {
            if (report.Components.Count == 0)
            {
                PlatformStatusCard.Visibility = Visibility.Collapsed;
                return;
            }

            PlatformStatusTitle.Text = LocalizationService.GetString("Platform_StatusTitle");
            PlatformStatusCard.Visibility = Visibility.Visible;
            PlatformStatusPanel.Children.Clear();

            foreach (var item in report.Components)
            {
                var dotKey = item.State switch
                {
                    PlatformComponentState.Active => "SuccessGreen",
                    PlatformComponentState.Warning => "WarningBrush",
                    _ => "TextMutedBrush",
                };

                var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
                row.Children.Add(Themed(new TextBlock
                {
                    Text = "●",
                    VerticalAlignment = VerticalAlignment.Center,
                }, dotKey));
                row.Children.Add(Themed(new TextBlock
                {
                    Text = LocalizationService.GetString(item.LabelKey),
                    TextWrapping = TextWrapping.WrapWholeWords,
                    VerticalAlignment = VerticalAlignment.Center,
                }, "TextMutedBrush"));
                PlatformStatusPanel.Children.Add(row);
            }
        });
    }

    private HyperlinkButton BuildAutoFixButton(string checkId)
    {
        var fix = new HyperlinkButton
        {
            Content = LocalizationService.GetString("Posture_Fix"),
            Padding = new Thickness(0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        fix.Click += async (_, _) => await RunAutoFixAsync(checkId, fix);
        return fix;
    }

    /// <summary>Applique la correction en arrière-plan (script admin si nécessaire) puis rafraîchit la note.</summary>
    private async Task RunAutoFixAsync(string checkId, HyperlinkButton button)
    {
        if (_fixRunning)
            return;
        _fixRunning = true;
        button.IsEnabled = false;
        PostureFixStatusText.Visibility = Visibility.Visible;
        PostureFixStatusText.Text = LocalizationService.GetString("Posture_FixRunning");
        try
        {
            var result = await PostureFixService.FixAsync(
                checkId,
                WinUiServiceHost.Instance.Container,
                (msg, title) => _confirm.ConfirmYesNo(msg, title, warning: true));

            PostureFixStatusText.Text = result.Message;
            PostureFixStatusText.Visibility = string.IsNullOrEmpty(result.Message)
                ? Visibility.Collapsed
                : Visibility.Visible;

            if (result.Status is PostureFixStatus.Done or PostureFixStatus.NeedsRestart)
                await WinUiServiceHost.Instance.RefreshOverviewAsync(this);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OverviewPage", $"PostureFix {checkId}", ex);
            PostureFixStatusText.Text = ex.Message;
            PostureFixStatusText.Visibility = Visibility.Visible;
        }
        finally
        {
            _fixRunning = false;
            button.IsEnabled = true;
        }
    }

    private void InvokePostureFix(string uri)
    {
        if (TryNavigatePosturePanel(uri))
            return;

        foreach (var candidate in uri.Split('|').Select(c => c.Trim()))
        {
            try
            {
                LaunchFixUri(candidate);
                return;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OverviewPage", $"PostureFix échoué ({candidate})", ex);
            }
        }
    }

    private bool TryNavigatePosturePanel(string uri)
    {
        const string prefix = "optiscan://panel/";
        if (!uri.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var segment = uri[prefix.Length..].Trim().TrimEnd('/');
        var slashIndex = segment.IndexOfAny(['/', '?', '#']);
        if (slashIndex >= 0)
            segment = segment[..slashIndex];

        var panelId = segment.ToLowerInvariant() switch
        {
            "antivirus" => OptiscanStrings.PanelIds.Antivirus,
            "options" => OptiscanStrings.PanelIds.Options,
            "history" => OptiscanStrings.PanelIds.History,
            "clean" => OptiscanStrings.PanelIds.Clean,
            _ => OptiscanStrings.PanelIds.Overview,
        };

        WinUiServiceHost.Instance.Container.Navigation?.NavigateTo(panelId);
        return true;
    }

    private static void LaunchFixUri(string uri)
    {
        var parts = uri.Split(' ', 2);
        string file = parts[0];
        string args = parts.Length > 1 ? parts[1] : string.Empty;
        Process.Start(new ProcessStartInfo(file) { UseShellExecute = true, Arguments = args });
    }

    // Le lien « Mettre à jour maintenant » ne faisait que naviguer : il lance désormais la mise à jour,
    // comme la vignette « Mise à jour ».
    private void SigUpdateLink_Click(object sender, RoutedEventArgs e) =>
        ActionUpdateSig_Click(sender, e);

    public void UpdateSignaturesSummary(string yaraPackVer, string yaraLastMaj, string clamDbVer, string clamLastMaj)
    {
        RunOnUi(() =>
        {
            ClamSigText.Text = LocalizationService.Format(
                "Overview_SigClamLine",
                VersionDisplayHelper.NormalizeForDisplay(string.IsNullOrWhiteSpace(clamDbVer) ? "—" : clamDbVer),
                string.IsNullOrWhiteSpace(clamLastMaj) ? "—" : clamLastMaj);
            YaraSigText.Text = LocalizationService.Format(
                "Overview_SigYaraLine",
                string.IsNullOrWhiteSpace(yaraPackVer) ? "—" : yaraPackVer,
                string.IsNullOrWhiteSpace(yaraLastMaj) ? "—" : yaraLastMaj);
        });
    }

    public void UpdateAntivirusCardStatus(bool clamAvOk, int yaraRulesCount, string? clamEngineMode = null)
    {
        RunOnUi(() =>
        {
            if (clamAvOk && !string.IsNullOrWhiteSpace(clamEngineMode))
                AntivirusCardText.Text = LocalizationService.Format("Overview_ClamEngine", clamEngineMode);
            else
                AntivirusCardText.Text = clamAvOk
                    ? LocalizationService.GetString("Overview_ClamActive")
                    : LocalizationService.GetString("Overview_ClamMissing");

            if (yaraRulesCount > 0)
                AntivirusCardText.Text += " — " + LocalizationService.Format("Overview_YaraLoaded", yaraRulesCount);
        });
    }

    public void UpdateProtectionStatistics(IReadOnlyList<ScanSession> history)
    {
        RunOnUi(() =>
        {
            var total = WinUiServiceHost.Instance.Container.UserPreferencesAccessor.Current.TotalScansCount;
            ProtectionStatsText.Text = OverviewProtectionStatsFormatter.Format(history, total, DateTime.Now);
            ProtectionStatsUpdated.Text = LocalizationService.Format(
                "Overview_UpdatedAt",
                DateTime.Now.ToString("G", LocalizationService.CurrentCulture));
        });
    }

    public void UpdateLastScanSummary(ScanSession? lastSession) =>
        RunOnUi(() =>
        {
            var text = ScanLastScanDisplay.FormatDetailed(lastSession);
            LastScanText.Text = text;
            HeroLastScanText.Text = lastSession == null
                ? LocalizationService.GetString("Common_Never")
                : lastSession.StartedAt.ToString("g", LocalizationService.CurrentCulture);
        });
}
