using MaterialDesignThemes.Wpf;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue d'ensemble (tableau de bord) : état de la protection, dernière analyse,
    /// statistiques et recommandations. Mise à jour via des méthodes publiques appelées par MainWindow.
    /// </summary>
    public partial class OverviewControl : System.Windows.Controls.UserControl
    {
        public OverviewControl()
        {
            InitializeComponent();
            Loaded += (_, _) => optiSCAN.ThemeManager.ThemeChanged += SurChangementTheme;
            Unloaded += (_, _) => optiSCAN.ThemeManager.ThemeChanged -= SurChangementTheme;
        }

        private void SurChangementTheme(object? sender, bool isDark)
        {
            Dispatcher.InvokeAsync(() =>
            {
                txtProtectionHeadline?.ClearValue(TextBlock.ForegroundProperty);
                txtProtectionStatus?.ClearValue(TextBlock.ForegroundProperty);
                txtOverviewClamAvStatus?.ClearValue(TextBlock.ForegroundProperty);
                txtOverviewYaraCount?.ClearValue(TextBlock.ForegroundProperty);
            });
        }

        /// <summary>Met à jour le bloc « Statistiques de protection » depuis l'historique des scans.</summary>
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
                    sb.AppendLine("• Aucune analyse enregistrée sur les 30 derniers jours.");
                else
                {
                    sb.AppendLine($"• Analyses enregistrées : {sessions30.ToString("N0", cult)}");
                    sb.AppendLine($"• Fichiers parcourus (cumul) : {files30.ToString("N0", cult)}");
                    sb.AppendLine($"• Menaces détectées (cumul) : {threats30.ToString("N0", cult)}");
                }

                sb.AppendLine();
                sb.Append($"Depuis l’installation de cette copie d’optiSCAN : {totalLifetime.ToString("N0", cult)} analyse(s) comptabilisée(s) dans les préférences.");
                sb.AppendLine();
                sb.Append("Le détail par session reste disponible dans l’onglet Historique.");

                txtProtectionStatsBody.Text = sb.ToString().TrimEnd();

                if (txtProtectionStatsUpdated != null)
                    txtProtectionStatsUpdated.Text =
                        $"Actualisé : {now.ToString("dd/MM/yyyy HH:mm:ss", cult)}";
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
                    txtOverviewClamDbVer.Text = string.IsNullOrWhiteSpace(clamDbVer) || clamDbVer == "Inconnue" ? "—" : clamDbVer;
                if (txtOverviewClamDbMaj != null)
                    txtOverviewClamDbMaj.Text = string.IsNullOrWhiteSpace(clamLastMaj) ? "—" : clamLastMaj;
            });
        }

        /// <summary>Met à jour la version de la base de signatures affichée.</summary>
        public void UpdateSignatureVersion(string version)
            => UpdateSignaturesSummary("—", "—", version, "—");

        /// <summary>Met à jour la date/heure du dernier scan.</summary>
        public void UpdateLastScanTime(DateTime? lastScan)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtLastScan == null) return;
                txtLastScan.Text = lastScan.HasValue
                    ? lastScan.Value.ToString("dd/MM/yyyy HH:mm")
                    : "Jamais";
            });
        }

        /// <summary>
        /// severity : 0 = succès (vert), 1 = attention (or), 2 = neutre (surface).
        /// </summary>
        public void UpdateRecommendations(
            string signaturesLine, int signaturesSeverity,
            string hygieneLine, int hygieneSeverity,
            string activityLine, int activitySeverity)
        {
            Dispatcher.InvokeAsync(() =>
            {
                ApplyRecommendationRow(brRecSignatures, txtRecSignatures, icRecSignatures, signaturesLine, signaturesSeverity);
                ApplyRecommendationRow(brRecHygiene, txtRecHygiene, icRecHygiene, hygieneLine, hygieneSeverity);
                ApplyRecommendationRow(brRecActivity, txtRecActivity, icRecActivity, activityLine, activitySeverity);
            });
        }

        private static void ApplyRecommendationRow(Border? border, TextBlock? text, PackIcon? icon, string line, int severity)
        {
            if (border == null || text == null) return;
            text.Text = line;
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
                default:
                    kind = PackIconKind.History;
                    bg = border.TryFindResource("SurfaceBg") as Brush;
                    fg = text.TryFindResource("TextMedium") as Brush;
                    ifg = icon?.TryFindResource("SuccessGreen") as Brush;
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

        /// <summary>Met à jour le message de statut de protection.</summary>
        public void UpdateProtectionStatus(bool isProtected, string? message = null, string? headline = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtProtectionStatus == null) return;
                if (txtProtectionHeadline != null)
                {
                    txtProtectionHeadline.Text = string.IsNullOrWhiteSpace(headline)
                        ? (isProtected ? "Votre ordinateur est protégé" : "Protection incomplète")
                        : headline!;
                    txtProtectionHeadline.Foreground =
                        ThemeUiBrushes.Get("TextDark", txtProtectionHeadline);
                }
                txtProtectionStatus.Text = message
                    ?? (isProtected
                        ? "Les définitions sont à jour."
                        : "Vérifiez ClamAV, les règles YARA et les mises à jour des signatures.");

                txtProtectionStatus.Foreground = isProtected
                    ? ThemeUiBrushes.Get("SuccessGreen", txtProtectionStatus)
                    : ThemeUiBrushes.Get("AlertGold", txtProtectionStatus)
                      ?? ThemeUiBrushes.Get("TextMuted", txtProtectionStatus);
            });
        }

        /// <summary>Met à jour la carte "État Antivirus" (ClamAV + nombre de règles YARA).</summary>
        public void UpdateAntivirusCardStatus(bool clamAvOk, int yaraRulesCount)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtOverviewClamAvStatus != null)
                {
                    txtOverviewClamAvStatus.Text = clamAvOk ? "Actif" : "Non installé";
                    txtOverviewClamAvStatus.Foreground = clamAvOk
                        ? ThemeUiBrushes.Get("SuccessGreen", txtOverviewClamAvStatus)
                        : ThemeUiBrushes.Get("DangerRed", txtOverviewClamAvStatus);
                }

                if (txtOverviewYaraCount != null)
                {
                    txtOverviewYaraCount.Text = yaraRulesCount > 0
                        ? $"{yaraRulesCount:N0} règles"
                        : "Non chargé";
                    txtOverviewYaraCount.Foreground = yaraRulesCount > 0
                        ? ThemeUiBrushes.Get("TextAccent", txtOverviewYaraCount)
                        : ThemeUiBrushes.Get("TextMuted", txtOverviewYaraCount);
                }
            });
        }

        // ── Cartes d'action → navigation ────────────────────────────────────
        // Handler pour MouseLeftButtonUp sur les Borders des cartes d'action

        private void ActionCard_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            // Le Tag est porté par le Border qui émet l'événement
            string? target = null;
            if (sender is System.Windows.Controls.Border border && border.Tag is string t)
                target = t;

            if (target == null) return;

            // Navigation et actions via ServiceContainer (pas de cast vers MainWindow) :
            // la vue reste utilisable en design-time et dans les tests.
            var container = Services.ServiceContainer.Default;

            if (target == OptiscanStrings.ActionIds.Update)
            {
                container.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                container.RequestFocusAntivirusSignaturesTab();
                container.TriggerSignatureUpdate(); // MainWindow écoute cet event
            }
            else
            {
                container.Navigation?.NavigateTo(target);
            }
        }
    }
}