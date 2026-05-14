namespace optiSCAN.Views
{
    public partial class OverviewControl : System.Windows.Controls.UserControl
    {
        public OverviewControl()
        {
            InitializeComponent();
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

        /// <summary>Met à jour le message de statut de protection.</summary>
        public void UpdateProtectionStatus(bool isProtected, string? message = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtProtectionStatus == null) return;
                txtProtectionStatus.Text = message
                    ?? (isProtected ? "Les définitions sont à jour." : "Protection dégradée — vérifiez ClamAV.");
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
                        ? System.Windows.Media.Brushes.Green
                        : System.Windows.Media.Brushes.OrangeRed;
                }

                if (txtOverviewYaraCount != null)
                    txtOverviewYaraCount.Text = yaraRulesCount > 0
                        ? $"{yaraRulesCount:N0} règles"
                        : "Non chargé";
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

            // Audit A2 : navigation + déclenchement via ServiceContainer plutôt
            // que cast vers MainWindow. Cette vue est ainsi testable et
            // utilisable en design-time.
            var container = Services.ServiceContainer.Default;

            if (target == "Update")
            {
                container.Navigation?.NavigateTo("Antivirus");
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