using MaterialDesignThemes.Wpf;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using System.Diagnostics;
using System.Linq;
using optiSCAN.Strings;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue d'ensemble : hero (protection + dernière analyse), actions, statistiques et recommandations.
    /// </summary>
    public partial class OverviewControl : System.Windows.Controls.UserControl, IOverviewPanel
    {
        private IViewServices? _services;

        public void Bind(IViewServices services) => _services = services;
        public OverviewControl()
        {
            InitializeComponent();
            Loaded += (_, _) =>
            {
                ApplyStaticLocalizedTexts();
                optiSCAN.ThemeManager.ThemeChanged += SurChangementTheme;
            };
            Unloaded += (_, _) => optiSCAN.ThemeManager.ThemeChanged -= SurChangementTheme;
        }

        private void SurChangementTheme(object? sender, bool isDark)
        {
            Dispatcher.InvokeAsync(() =>
            {
                txtProtectionHeadline?.ClearValue(TextBlock.ForegroundProperty);
                txtOverviewClamAvStatus?.ClearValue(TextBlock.ForegroundProperty);
                txtOverviewYaraCount?.ClearValue(TextBlock.ForegroundProperty);

                if (shieldImage != null)
                {
                    shieldImage.ClearValue(System.Windows.Controls.Image.EffectProperty);
                    shieldImage.Effect = TryFindResource("HeroShieldPulseGlow") as System.Windows.Media.Effects.Effect;
                }
            });
        }

        public void UpdateProtectionStatistics(IReadOnlyList<ScanSession> history)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtProtectionStatsBody == null) return;

                var now = DateTime.Now;
                int totalLifetime = (_services?.UserPreferencesAccessor ?? new DefaultUserPreferencesAccessor())
                    .Current.TotalScansCount;
                var cult = CultureInfo.CurrentCulture;

                txtProtectionStatsBody.Text = OverviewProtectionStatsFormatter.Format(
                    history, totalLifetime, now);

                if (txtProtectionStatsUpdated != null)
                    txtProtectionStatsUpdated.Text =
                        LocalizationService.Format("Overview_UpdatedAt", now.ToString("G", cult));
            });
        }

        public void UpdateLastScanSummary(ScanSession? lastSession)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtLastScan == null) return;
                txtLastScan.Text = ScanLastScanDisplay.FormatDetailed(lastSession);
            });
        }

        /// <summary>Met à jour le bloc YARA | ClamAV (version base + dernières MAJ).</summary>
        public void UpdateSignaturesSummary(string yaraPackVer, string yaraLastMaj, string clamDbVer, string clamLastMaj)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtOverviewYaraPackVer != null)
                    txtOverviewYaraPackVer.Text = string.IsNullOrWhiteSpace(yaraPackVer) ? "—" : yaraPackVer;
                if (txtOverviewYaraPackMaj != null)
                    txtOverviewYaraPackMaj.Text = string.IsNullOrWhiteSpace(yaraLastMaj) ? "—" : yaraLastMaj;
                if (txtOverviewClamDbVer != null)
                    txtOverviewClamDbVer.Text = VersionDisplayHelper.NormalizeForDisplay(
                        string.IsNullOrWhiteSpace(clamDbVer) ? null : clamDbVer);
                if (txtOverviewClamDbMaj != null)
                    txtOverviewClamDbMaj.Text = string.IsNullOrWhiteSpace(clamLastMaj) ? "—" : clamLastMaj;
            });
        }

        /// <summary>Met à jour la version de la base de signatures affichée.</summary>
        public void UpdateSignatureVersion(string version)
            => UpdateSignaturesSummary("—", "—", version, "—");

        public void UpdateSecurityPosture(SecurityPostureReport report)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtSecurityScore != null)
                    txtSecurityScore.Text = report.Score.ToString(CultureInfo.CurrentCulture);

                if (postureIssuesPanel == null) return;
                postureIssuesPanel.Children.Clear();

                var failed = report.Checks.Where(c => !c.Passed).Take(4).ToList();
                if (failed.Count == 0)
                {
                    postureIssuesPanel.Children.Add(new TextBlock
                    {
                        Text = LocalizationService.GetString("Posture_AllGood"),
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = (double)FindResource("FontSize.Micro"),
                        LineHeight = 14,
                        Foreground = (Brush)FindResource("TextDark"),
                    });
                    return;
                }

                foreach (var check in failed)
                {
                    var row = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
                    row.Children.Add(new TextBlock
                    {
                        Text = "• " + check.Title,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = (double)FindResource("FontSize.Micro"),
                        LineHeight = 14,
                        Foreground = (Brush)FindResource("TextDark"),
                        VerticalAlignment = VerticalAlignment.Center,
                    });

                    if (!string.IsNullOrWhiteSpace(check.FixUri))
                    {
                        var fix = new Hyperlink(new Run(LocalizationService.GetString("Posture_Fix")))
                        {
                            Tag = check.FixUri,
                            Foreground = (Brush)FindResource("TextAccent"),
                        };
                        fix.Click += PostureFix_Click;
                        row.Children.Add(new TextBlock
                        {
                            Margin = new Thickness(6, 0, 0, 0),
                            FontSize = (double)FindResource("FontSize.Micro"),
                            VerticalAlignment = VerticalAlignment.Center,
                            Inlines = { fix },
                        });
                    }

                    postureIssuesPanel.Children.Add(row);
                }
            });
        }

        public void UpdatePlatformProtectionStatus(PlatformProtectionStatusReport report)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (platformStatusPanel == null)
                    return;

                platformStatusPanel.Children.Clear();
                foreach (var item in report.Components)
                {
                    var brush = item.State switch
                    {
                        PlatformComponentState.Active => (Brush)FindResource("SuccessGreen"),
                        PlatformComponentState.Warning => (Brush)FindResource("AlertGold"),
                        PlatformComponentState.Inactive => (Brush)FindResource("TextMuted"),
                        _ => (Brush)FindResource("TextDark"),
                    };

                    var row = new StackPanel
                    {
                        Orientation = System.Windows.Controls.Orientation.Horizontal,
                        Margin = new Thickness(0, 0, 0, 4),
                    };
                    row.Children.Add(new TextBlock
                    {
                        Text = "●",
                        Foreground = brush,
                        FontSize = (double)FindResource("FontSize.Micro"),
                        Margin = new Thickness(0, 0, 6, 0),
                        VerticalAlignment = VerticalAlignment.Center,
                    });
                    row.Children.Add(new TextBlock
                    {
                        Text = LocalizationService.GetString(item.LabelKey),
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = (double)FindResource("FontSize.Micro"),
                        LineHeight = 14,
                        Foreground = (Brush)FindResource("TextDark"),
                        VerticalAlignment = VerticalAlignment.Center,
                    });
                    platformStatusPanel.Children.Add(row);
                }
            });
        }

        private void PostureFix_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Hyperlink link || link.Tag is not string uri)
                return;

            if (TryApplyPostureFix(uri))
                return;

            if (TryNavigatePosturePanel(uri))
                return;

            // Format FixUri : "primaire|repli" ou "uri" simple.
            // Le repli est tenté si le primaire lève une exception (ex. ms-settings inconnu sur Win10).
            var candidates = uri.Split('|');
            Exception? lastEx = null;
            foreach (var candidate in candidates)
            {
                try
                {
                    LaunchFixUri(candidate.Trim());
                    return; // succès — on s'arrête
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                }
            }
            if (lastEx != null)
                AppLogger.Warn("OverviewControl", $"PostureFix — tous les replis ont échoué ({uri})", lastEx);
        }

        private bool TryApplyPostureFix(string uri)
        {
            const string prefix = "optiscan://fix/";
            if (!uri.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return false;

            var action = uri[prefix.Length..].Trim().TrimEnd('/');
            if (_services is not IOptionsServices && action is not "scan")
            {
                AppLogger.Warn("OverviewControl", $"PostureFix — services indisponibles ({action})");
                return true;
            }

            switch (action)
            {
                case "protection":
                    if (_services is IOptionsServices protection)
                    {
                        protection.ApplyRealtimeProtection(true);
                        if (protection.UserPreferencesAccessor.Current.UsePlatformProtectionService)
                            protection.ApplyPlatformProtectionService(true);
                    }
                    break;
                case "sigauto":
                    if (_services is IOptionsServices signatures)
                        signatures.ApplySignatureAutoUpdate(true);
                    break;
                case "scan":
                    _services?.RequestQuickScan();
                    break;
                case "shares":
                    _ = RemoveExposedSharesWithConfirmationAsync();
                    break;
                default:
                    AppLogger.Warn("OverviewControl", $"PostureFix — action inconnue : {action}");
                    break;
            }

            return true;
        }

        /// <summary>
        /// Liste les partages, demande confirmation (action destructive : un partage peut être voulu),
        /// puis supprime hors thread UI (UAC + net share peuvent durer plusieurs secondes).
        /// </summary>
        private async Task RemoveExposedSharesWithConfirmationAsync()
        {
            try
            {
                var names = await Task.Run(() => SecurityPostureService.ListExposedShareNames()).ConfigureAwait(true);
                if (names.Count == 0)
                {
                    _services?.RequestProtectionStateRefresh();
                    return;
                }

                var message = string.Format(
                    LocalizationService.CurrentCulture,
                    LocalizationService.GetString("Posture_SharesConfirm"),
                    string.Join(Environment.NewLine, names.Select(n => "  • " + n)));
                var title = LocalizationService.GetString("Posture_SharesConfirmTitle");
                var owner = Window.GetWindow(this);
                var answer = owner != null
                    ? System.Windows.MessageBox.Show(owner, message, title,
                        MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
                    : System.Windows.MessageBox.Show(message, title,
                        MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                if (answer != MessageBoxResult.Yes)
                    return;

                bool removed = await Task.Run(() => SecurityPostureService.TryRemoveExposedShares(names))
                    .ConfigureAwait(true);
                if (!removed)
                    AppLogger.Warn("OverviewControl", "Suppression des partages exposés incomplète");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OverviewControl", "Suppression des partages exposés", ex);
            }

            _services?.RequestProtectionStateRefresh();
        }

        private bool TryNavigatePosturePanel(string uri)
        {
            const string prefix = "optiscan://panel/";
            if (!uri.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return false;

            var segment = uri[prefix.Length..].Trim().TrimEnd('/');
            var slash = segment.IndexOfAny(['/', '?', '#']);
            if (slash >= 0)
                segment = segment[..slash];

            var panelId = segment.ToLowerInvariant() switch
            {
                "antivirus" => OptiscanStrings.PanelIds.Antivirus,
                "options" => OptiscanStrings.PanelIds.Options,
                "history" => OptiscanStrings.PanelIds.History,
                "clean" => OptiscanStrings.PanelIds.Clean,
                "overview" => OptiscanStrings.PanelIds.Overview,
                _ => null,
            };

            if (panelId == null)
            {
                AppLogger.Warn("OverviewControl", $"PostureFix — panneau inconnu : optiscan://panel/{segment}");
                panelId = OptiscanStrings.PanelIds.Overview;
            }

            _services!.Navigation?.NavigateTo(panelId);
            return true;
        }

        private static void LaunchFixUri(string uri)
        {
            if (uri.StartsWith("control.exe", StringComparison.OrdinalIgnoreCase))
            {
                var parts = uri.Split(' ', 2);
                Process.Start(new ProcessStartInfo(parts[0])
                {
                    UseShellExecute = true,
                    Arguments = parts.Length > 1 ? parts[1] : string.Empty,
                });
                return;
            }

            if (uri.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                var space = uri.IndexOf(' ', StringComparison.Ordinal);
                var file = space >= 0 ? uri[..space] : uri;
                var args = space >= 0 ? uri[(space + 1)..] : string.Empty;
                Process.Start(new ProcessStartInfo(file)
                {
                    UseShellExecute = true,
                    Arguments = args,
                });
                return;
            }

            Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
        }

        private void RecHygieneSigUpdate_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            e.Handled = true;
            NavigateToSignaturesAndUpdate();
        }

        public void UpdateRecommendations(
            string hygieneLine, int hygieneSeverity,
            bool showSigUpdateLink = false,
            string? fixAction = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                ApplyRecommendationRow(brRecHygiene, txtRecHygiene, icRecHygiene, hygieneLine, hygieneSeverity, showSigUpdateLink, fixAction);
            });
        }

        private void ApplyRecommendationRow(Border? border, TextBlock? text, PackIcon? icon, string line, int severity, bool showUpdateLink = false, string? fixAction = null)
        {
            if (border == null || text == null) return;

            text.FontSize = (double)text.FindResource("FontSize.Small");
            text.LineHeight = 16;

            // Si lien demandé : utiliser Inlines pour intercaler texte + hyperlien.
            // Sinon : Text simple (efface tout lien précédent).
            text.Inlines.Clear();
            if (showUpdateLink || !string.IsNullOrWhiteSpace(fixAction))
            {
                border.Cursor = System.Windows.Input.Cursors.Hand;
                border.MouseLeftButtonUp -= RecHygieneSigUpdate_Click;
                if (showUpdateLink)
                    border.MouseLeftButtonUp += RecHygieneSigUpdate_Click;

                text.Inlines.Add(new Run(line + " "));
                var link = new Hyperlink(new Run(LocalizationService.GetString(
                    showUpdateLink ? "Rec_SigStaleAction" : "Posture_Fix")))
                {
                    Foreground = text.TryFindResource("TextAccent") as Brush
                                 ?? text.TryFindResource("AlertGold") as Brush,
                    Tag = fixAction,
                };
                link.Click += (_, e) =>
                {
                    e.Handled = true;
                    if (showUpdateLink)
                        NavigateToSignaturesAndUpdate();
                    else if (link.Tag is string action)
                        TryApplyPostureFix("optiscan://fix/" + action);
                };
                text.Inlines.Add(link);
            }
            else
            {
                border.Cursor = null;
                border.MouseLeftButtonUp -= RecHygieneSigUpdate_Click;
                text.Inlines.Add(new Run(line));
            }
            Brush? bg = null, fg = null, ifg = null;
            PackIconKind kind = PackIconKind.InformationOutline;
            switch (severity)
            {
                case 0:
                    kind = PackIconKind.CheckCircle;
                    bg = border.TryFindResource("SuccessBg") as Brush;
                    fg = text.TryFindResource("SuccessGreen") as Brush;
                    ifg = icon?.TryFindResource("SuccessGreen") as Brush;
                    break;
                case 1:
                    kind = PackIconKind.Alert;
                    bg = border.TryFindResource("AlertBg") as Brush;
                    fg = text.TryFindResource("AlertGold") as Brush;
                    ifg = icon?.TryFindResource("AlertGoldLight") as Brush;
                    break;
                case 2:
                    // Tout va bien, activite normale -> vert
                    kind = PackIconKind.CheckCircle;
                    bg = border.TryFindResource("SuccessBg") as Brush;
                    fg = text.TryFindResource("SuccessGreen") as Brush;
                    ifg = icon?.TryFindResource("SuccessGreen") as Brush;
                    break;
                default:
                    // Severity 3 = conseil preventif (info) -> bleu neutre
                    kind = PackIconKind.InformationOutline;
                    bg = border.TryFindResource("InfoBg") as Brush ?? border.TryFindResource("SurfaceBg") as Brush;
                    fg = text.TryFindResource("TextAccent") as Brush ?? text.TryFindResource("TextMedium") as Brush;
                    ifg = icon?.TryFindResource("TextAccent") as Brush;
                    break;
            }
            if (bg != null) border.Background = bg;
            if (fg != null) text.Foreground = fg;
            if (icon != null)
            {
                icon.Kind = kind;
                if (ifg != null) icon.Foreground = ifg;
            }
        }

        /// <summary>Met a jour le titre de protection affiche dans le hero.</summary>
        public void UpdateProtectionHeadline(bool isProtected, string? headline = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtProtectionHeadline == null) return;
                txtProtectionHeadline.Text = string.IsNullOrWhiteSpace(headline)
                    ? (isProtected
                        ? LocalizationService.GetString("Overview_Protected")
                        : LocalizationService.GetString("Overview_ProtectionIncomplete"))
                    : headline!;
                txtProtectionHeadline.Foreground =
                    ThemeUiBrushes.Get("TextDark", txtProtectionHeadline);
            });
        }

        /// <summary>Met a jour la carte Etat de protection (ClamAV + regles YARA).</summary>
        public void UpdateAntivirusCardStatus(bool clamAvOk, int yaraRulesCount, string? clamEngineMode = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtOverviewClamAvStatus != null)
                {
                    if (clamAvOk && !string.IsNullOrWhiteSpace(clamEngineMode))
                    {
                        txtOverviewClamAvStatus.Text = LocalizationService.Format("Overview_ClamEngine", clamEngineMode);
                    }
                    else
                    {
                        txtOverviewClamAvStatus.Text = clamAvOk
                            ? LocalizationService.GetString("Overview_ClamActive")
                            : LocalizationService.GetString("Overview_ClamMissing");
                    }
                    txtOverviewClamAvStatus.Foreground = clamAvOk
                        ? ThemeUiBrushes.Get("SuccessGreen", txtOverviewClamAvStatus)
                        : ThemeUiBrushes.Get("DangerRed", txtOverviewClamAvStatus);
                }

                if (txtOverviewYaraCount != null)
                {
                    txtOverviewYaraCount.Text = yaraRulesCount > 0
                        ? LocalizationService.Format("Overview_YaraLoaded", yaraRulesCount)
                        : LocalizationService.GetString("Overview_YaraMissing");
                    txtOverviewYaraCount.Foreground = yaraRulesCount > 0
                        ? ThemeUiBrushes.Get("TextAccent", txtOverviewYaraCount)
                        : ThemeUiBrushes.Get("TextMuted", txtOverviewYaraCount);
                }
            });
        }

        private void ApplyStaticLocalizedTexts()
        {
            if (txtProtectionHeadline != null && string.IsNullOrWhiteSpace(txtProtectionHeadline.Text))
                txtProtectionHeadline.Text = LocalizationService.GetString("Overview_Protected");
        }

        public void ApplyElevationBanner()
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (bannerPartialScan == null) return;
                bool elevated = ElevationHelper.IsRunningElevated();
                bannerPartialScan.Visibility = elevated ? Visibility.Collapsed : Visibility.Visible;
            });
        }

        private void BtnRunAsAdmin_Click(object sender, RoutedEventArgs e)
        {
            bool ok = ElevationHelper.RelaunchElevated();
            if (ok)
                System.Windows.Application.Current.Shutdown();
        }

        private void ActionCard_Click(object sender, RoutedEventArgs e)
        {
            string? target = null;
            if (sender is FrameworkElement fe && fe.Tag is string t)
                target = t;

            if (target == null) return;

            if (target == OptiscanStrings.ActionIds.Update)
            {
                _services!.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                _services.RequestFocusAntivirusSignaturesTab();
                _services.TriggerSignatureUpdate();
            }
            else
            {
                _services!.Navigation?.NavigateTo(target);
            }
        }

        private void NavigateToSignaturesAndUpdate()
        {
            _services!.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
            _services.RequestFocusAntivirusSignaturesTab();
            _services.TriggerSignatureUpdate();
        }
    }
}
