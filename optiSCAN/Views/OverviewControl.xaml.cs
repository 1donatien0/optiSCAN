using MaterialDesignThemes.Wpf;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using System.Diagnostics;
using System.Linq;
using optiSCAN.Strings;
using System.Globalization;
using System.Text;
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
    public partial class OverviewControl : System.Windows.Controls.UserControl
    {
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
                var cutoff = now.AddDays(-30);
                int sessions30 = 0;
                long files30 = 0;
                long threats30 = 0;

                foreach (var s in history)
                {
                    if (s.StartedAt < cutoff) continue;
                    sessions30++;
                    files30 += Math.Max(0, s.FilesScanned);
                    threats30 += Math.Max(0, s.ThreatsFound);
                }

                int totalLifetime = UserPreferences.Current.TotalScansCount;
                var cult = CultureInfo.CurrentCulture;

                var sb = new StringBuilder();
                if (sessions30 == 0)
                    sb.AppendLine(LocalizationService.GetString("Overview_StatsNone30"));
                else
                {
                    sb.AppendLine(LocalizationService.Format("Overview_StatsScans", sessions30.ToString("N0", cult)));
                    sb.AppendLine(LocalizationService.Format("Overview_StatsFiles", files30.ToString("N0", cult)));
                    sb.AppendLine(LocalizationService.Format("Overview_StatsThreats", threats30.ToString("N0", cult)));
                }

                sb.AppendLine();
                sb.Append(LocalizationService.Format("Overview_StatsLifetime", totalLifetime.ToString("N0", cult)));
                sb.AppendLine();
                sb.Append(LocalizationService.GetString("Overview_StatsHistoryHint"));

                txtProtectionStatsBody.Text = sb.ToString().TrimEnd();

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

        private void PostureFix_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Hyperlink link || link.Tag is not string uri)
                return;

            if (uri.StartsWith("optiscan://panel/", StringComparison.OrdinalIgnoreCase))
            {
                var panel = uri.EndsWith("/antivirus", StringComparison.OrdinalIgnoreCase)
                    ? OptiscanStrings.PanelIds.Antivirus
                    : OptiscanStrings.PanelIds.Options;
                ServiceContainer.Default.Navigation?.NavigateTo(panel);
                return;
            }

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
            }
            else
            {
                Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
            }
        }

        public void UpdateRecommendations(
            string hygieneLine, int hygieneSeverity,
            string activityLine, int activitySeverity,
            bool showSigUpdateLink = false)
        {
            Dispatcher.InvokeAsync(() =>
            {
                ApplyRecommendationRow(brRecHygiene, txtRecHygiene, icRecHygiene, hygieneLine, hygieneSeverity, showSigUpdateLink);
                ApplyRecommendationRow(brRecActivity, txtRecActivity, icRecActivity, activityLine, activitySeverity);
            });
        }

        private static void ApplyRecommendationRow(Border? border, TextBlock? text, PackIcon? icon, string line, int severity, bool showUpdateLink = false)
        {
            if (border == null || text == null) return;

            text.FontSize = (double)text.FindResource("FontSize.Small");
            text.LineHeight = 16;

            // Si lien demandé : utiliser Inlines pour intercaler texte + hyperlien.
            // Sinon : Text simple (efface tout lien précédent).
            text.Inlines.Clear();
            if (showUpdateLink)
            {
                border.Cursor = System.Windows.Input.Cursors.Hand;
                border.MouseLeftButtonUp -= RecHygieneSigUpdate_Click;
                border.MouseLeftButtonUp += RecHygieneSigUpdate_Click;

                text.Inlines.Add(new Run(line + " "));
                var link = new Hyperlink(new Run(LocalizationService.GetString("Rec_SigStaleAction")))
                {
                    Foreground = text.TryFindResource("TextAccent") as Brush
                                 ?? text.TryFindResource("AlertGold") as Brush,
                };
                link.Click += (_, e) =>
                {
                    e.Handled = true;
                    NavigateToSignaturesAndUpdate();
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
                    // Tout va bien, activité normale → vert
                    kind = PackIconKind.CheckCircle;
                    bg = border.TryFindResource("SuccessBg") as Brush;
                    fg = text.TryFindResource("SuccessGreen") as Brush;
                    ifg = icon?.TryFindResource("SuccessGreen") as Brush;
                    break;
                default:
                    // Severity 3 = conseil préventif (info) → bleu neutre
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

        /// <summary>Met à jour le titre de protection affiché dans le hero.</summary>
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

        /// <summary>Met à jour la carte « État de protection » (ClamAV + règles YARA).</summary>
        public void UpdateAntivirusCardStatus(bool clamAvOk, int yaraRulesCount, string? clamEngineMode = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtOverviewClamAvStatus != null)
                {
                    if (clamAvOk && !string.IsNullOrWhiteSpace(clamEngineMode))
                    {
                        txtOverviewClamAvStatus.Text = LocalizationService.Format(
                            "Overview_ClamEngine",
                            clamEngineMode);
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

        private static void RecHygieneSigUpdate_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            NavigateToSignaturesAndUpdate();
            e.Handled = true;
        }

        /// <summary>Accueil → Antivirus, onglet Signatures, puis lance la MAJ (progression visible).</summary>
        private static void NavigateToSignaturesAndUpdate()
        {
            var container = ServiceContainer.Default;
            container.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
            container.RequestFocusAntivirusSignaturesTab();
            container.TriggerSignatureUpdate();
        }

        private void ActionCard_Click(object sender, RoutedEventArgs e)
        {
            string? target = null;
            if (sender is FrameworkElement fe && fe.Tag is string t)
                target = t;

            if (target == null) return;

            var container = Services.ServiceContainer.Default;

            if (target == OptiscanStrings.ActionIds.Update)
            {
                NavigateToSignaturesAndUpdate();
            }
            else
            {
                container.Navigation?.NavigateTo(target);
            }
        }
    }
}
