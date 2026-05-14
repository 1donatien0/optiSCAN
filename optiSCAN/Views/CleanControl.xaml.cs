using System.IO;
using System.Runtime.InteropServices;
using System.Windows;

namespace optiSCAN.Views
{
    public partial class CleanControl : System.Windows.Controls.UserControl
    {
        // Analyse doit être lancée avant de pouvoir nettoyer
        private bool _analysed = false;

        public CleanControl()
        {
            InitializeComponent();
        }

        // ── Analyser ─────────────────────────────────────────────────────────
        private async void btnAnalyze_Click(object sender, RoutedEventArgs e)
        {
            btnAnalyze.IsEnabled = false;
            btnCleanNow.IsEnabled = false;
            _analysed = false;
            SetLog("=== ANALYSE EN COURS ===");

            await Task.Run(() =>
            {
                long tempWin = MeasureDir(Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp"));
                long tempUser = MeasureDir(Path.GetTempPath());
                long edgeCache = MeasureDir(EdgeCachePath());
                long chromeCache = MeasureDir(ChromeCachePath());
                long ffCache = MeasureDir(FirefoxCachePath());
                long braveCache = MeasureDir(BraveCachePath());
                long logsSize = MeasureDir(WindowsLogsPath());

                long sysTotal = tempWin + tempUser + logsSize;
                long browserTotal = edgeCache + chromeCache + ffCache + braveCache;
                long total = sysTotal + browserTotal;

                Dispatcher.Invoke(() =>
                {
                    txtTempSize.Text = FormatSize(sysTotal);
                    txtBrowserSize.Text = FormatSize(browserTotal);
                    txtTotalSize.Text = FormatSize(total);

                    AppendLog($"Temp Windows    : {FormatSize(tempWin)}");
                    AppendLog($"Temp utilisateur : {FormatSize(tempUser)}");
                    AppendLog($"Journaux système : {FormatSize(logsSize)}");
                    AppendLog($"Edge             : {FormatSize(edgeCache)}");
                    AppendLog($"Chrome           : {FormatSize(chromeCache)}");
                    AppendLog($"Firefox          : {FormatSize(ffCache)}");
                    AppendLog($"Brave            : {FormatSize(braveCache)}");
                    AppendLog($"─────────────────────────");
                    AppendLog($"Total libérable  : {FormatSize(total)}");
                    AppendLog("=== ANALYSE TERMINÉE ===");

                    _analysed = true;
                    btnCleanNow.IsEnabled = true;
                    txtAnalyzeHint.Visibility = Visibility.Collapsed;
                });
            });

            btnAnalyze.IsEnabled = true;
        }

        // ── Nettoyer ─────────────────────────────────────────────────────────
        private async void btnCleanNow_Click(object sender, RoutedEventArgs e)
        {
            if (!_analysed) return;

            // Audit A2 : on n'a plus besoin de remonter à MainWindow ; le statut
            // de nettoyage est géré localement par AppendLog et les compteurs
            // ci-dessous.
            btnAnalyze.IsEnabled = false;
            btnCleanNow.IsEnabled = false;
            AppendLog("=== NETTOYAGE EN COURS ===");

            await Task.Run(() =>
            {
                long freed = 0;

                if (chkTempWin?.IsChecked == true)
                {
                    string path = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp");
                    freed += CleanDir(path);
                    Dispatcher.Invoke(() => AppendLog($"Temp Windows nettoyé : {FormatSize(freed)}"));
                }
                if (chkTempUser?.IsChecked == true)
                {
                    long f = CleanDir(Path.GetTempPath());
                    freed += f;
                    Dispatcher.Invoke(() => AppendLog($"Temp utilisateur nettoyé : {FormatSize(f)}"));
                }
                if (chkRecycleBin?.IsChecked == true)
                {
                    SHEmptyRecycleBin(IntPtr.Zero, null, 0x0007);
                    Dispatcher.Invoke(() => AppendLog("Corbeille vidée."));
                }
                if (chkEdge?.IsChecked == true)
                {
                    long f = CleanDir(EdgeCachePath());
                    freed += f;
                    Dispatcher.Invoke(() => AppendLog($"Cache Edge : {FormatSize(f)}"));
                }
                if (chkChrome?.IsChecked == true)
                {
                    long f = CleanDir(ChromeCachePath());
                    freed += f;
                    Dispatcher.Invoke(() => AppendLog($"Cache Chrome : {FormatSize(f)}"));
                }
                if (chkFirefox?.IsChecked == true)
                {
                    long f = CleanDir(FirefoxCachePath());
                    freed += f;
                    Dispatcher.Invoke(() => AppendLog($"Cache Firefox : {FormatSize(f)}"));
                }
                if (chkBrave?.IsChecked == true)
                {
                    long f = CleanDir(BraveCachePath());
                    freed += f;
                    Dispatcher.Invoke(() => AppendLog($"Cache Brave : {FormatSize(f)}"));
                }
                if (chkLogs?.IsChecked == true)
                {
                    long f = CleanDir(WindowsLogsPath());
                    freed += f;
                    Dispatcher.Invoke(() => AppendLog($"Journaux système nettoyés : {FormatSize(f)}"));
                }

                Dispatcher.Invoke(() =>
                {
                    AppendLog($"─────────────────────────");
                    AppendLog($"Total libéré : {FormatSize(freed)}");
                    AppendLog("=== NETTOYAGE TERMINÉ ===");
                    txtTempSize.Text = "0 Mo";
                    txtBrowserSize.Text = "0 Mo";
                    txtTotalSize.Text = "0 Mo";
                    _analysed = false;
                    btnCleanNow.IsEnabled = false;
                    txtAnalyzeHint.Visibility = Visibility.Visible;
                    txtAnalyzeHint.Text = "  ✅ Nettoyage effectué";
                });
            });

            // L'appel à MainWindow.PerformCleanup() a été retiré (audit A2) :
            // c'était un signal de statut UI redondant avec AppendLog déjà émis.
            btnAnalyze.IsEnabled = true;
        }

        // ── Journalisation ───────────────────────────────────────────────────
        private void SetLog(string text)
        {
            if (txtCleanLog != null)
                txtCleanLog.Text = $"[{DateTime.Now:HH:mm:ss}] {text}\n";
        }

        public void AppendLog(string line)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtCleanLog == null) return;
                if (txtCleanLog.Text.StartsWith("Cliquez"))
                    txtCleanLog.Text = string.Empty;
                txtCleanLog.Text += $"[{DateTime.Now:HH:mm:ss}] {line}\n";
                txtCleanLog.ScrollToEnd();
            });
        }

        // ── Chemins de cache navigateurs ─────────────────────────────────────
        private static string LocalApp => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        private static string EdgeCachePath()   => Path.Combine(LocalApp, @"Microsoft\Edge\User Data\Default\Cache");
        private static string ChromeCachePath() => Path.Combine(LocalApp, @"Google\Chrome\User Data\Default\Cache");
        private static string BraveCachePath()  => Path.Combine(LocalApp, @"BraveSoftware\Brave-Browser\User Data\Default\Cache");
        private static string WindowsLogsPath() => Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"Logs");
        private static string FirefoxCachePath()
        {
            var profilesBase = Path.Combine(LocalApp, @"Mozilla\Firefox\Profiles");
            if (!Directory.Exists(profilesBase)) return string.Empty;
            foreach (var dir in Directory.EnumerateDirectories(profilesBase))
                if (dir.Contains(".default")) return Path.Combine(dir, "cache2");
            return string.Empty;
        }

        // ── Helpers fichiers ─────────────────────────────────────────────────
        private static long MeasureDir(string path)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return 0;
            try
            {
                long total = 0;
                foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    try { total += new FileInfo(f).Length; } catch { }
                }
                return total;
            }
            catch { return 0; }
        }

        private static long CleanDir(string path)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return 0;
            long freed = 0;
            try
            {
                foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    try { long s = new FileInfo(f).Length; File.Delete(f); freed += s; } catch { }
                }
            }
            catch { }
            return freed;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} o";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} Ko";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} Mo";
            return $"{bytes / (1024.0 * 1024 * 1024):F2} Go";
        }

        [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
    }
}