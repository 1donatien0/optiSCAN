using optiSCAN.Models;
using optiSCAN.Services;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue Nettoyer — analyse et suppression des fichiers temporaires, caches navigateurs et corbeille.
    /// L'analyse doit être exécutée avant de pouvoir lancer le nettoyage.
    /// </summary>
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
                long operaCache = MeasureDir(OperaCachePath());
                long vivaldiCache = MeasureDir(VivaldiCachePath());
                long arcCache = MeasureDir(ArcCachePath());
                long logsSize = MeasureDir(WindowsLogsPath());

                long sysTotal = tempWin + tempUser + logsSize;
                long browserTotal = edgeCache + chromeCache + ffCache + braveCache + operaCache + vivaldiCache + arcCache;
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
                    AppendLog($"Opera            : {FormatSize(operaCache)}");
                    AppendLog($"Vivaldi          : {FormatSize(vivaldiCache)}");
                    AppendLog($"Arc              : {FormatSize(arcCache)}");
                    AppendLog($"─────────────────────────");
                    AppendLog($"Total libérable  : {FormatSize(total)}");
                    AppendLog("=== ANALYSE TERMINÉE ===");

                    _analysed = true;
                    btnCleanNow.IsEnabled = true;
                });
            });

            btnAnalyze.IsEnabled = true;
        }

        // ── Nettoyer ─────────────────────────────────────────────────────────
        private async void btnCleanNow_Click(object sender, RoutedEventArgs e)
        {
            if (!_analysed) return;

            // Capturer les cases à cocher sur le thread UI : lire IsChecked dans
            // Task.Run provoque une InvalidOperationException WPF et peut fermer l'app.
            bool doTempWin = chkTempWin?.IsChecked == true;
            bool doTempUser = chkTempUser?.IsChecked == true;
            bool doRecycle = chkRecycleBin?.IsChecked == true;
            bool doEdge = chkEdge?.IsChecked == true;
            bool doChrome = chkChrome?.IsChecked == true;
            bool doFirefox = chkFirefox?.IsChecked == true;
            bool doBrave = chkBrave?.IsChecked == true;
            bool doOpera = chkOpera?.IsChecked == true;
            bool doVivaldi = chkVivaldi?.IsChecked == true;
            bool doArc = chkArc?.IsChecked == true;
            bool doLogs = chkLogs?.IsChecked == true;

            btnAnalyze.IsEnabled = false;
            btnCleanNow.IsEnabled = false;
            AppendLog("=== NETTOYAGE EN COURS ===");
            var cleanStarted = DateTime.Now;

            try
            {
                await Task.Run(() =>
                {
                    long freed = 0;

                    if (doTempWin)
                    {
                        string path = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp");
                        long f = CleanDir(path);
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Temp Windows nettoyé : {FormatSize(f)}"));
                    }
                    if (doTempUser)
                    {
                        long f = CleanDir(Path.GetTempPath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Temp utilisateur nettoyé : {FormatSize(f)}"));
                    }
                    if (doRecycle)
                    {
                        SHEmptyRecycleBin(IntPtr.Zero, null, 0x0007);
                        Dispatcher.Invoke(() => AppendLog("Corbeille vidée."));
                    }
                    if (doEdge)
                    {
                        long f = CleanDir(EdgeCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Edge : {FormatSize(f)}"));
                    }
                    if (doChrome)
                    {
                        long f = CleanDir(ChromeCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Chrome : {FormatSize(f)}"));
                    }
                    if (doFirefox)
                    {
                        long f = CleanDir(FirefoxCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Firefox : {FormatSize(f)}"));
                    }
                    if (doBrave)
                    {
                        long f = CleanDir(BraveCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Brave : {FormatSize(f)}"));
                    }
                    if (doOpera)
                    {
                        long f = CleanDir(OperaCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Opera : {FormatSize(f)}"));
                    }
                    if (doVivaldi)
                    {
                        long f = CleanDir(VivaldiCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Vivaldi : {FormatSize(f)}"));
                    }
                    if (doArc)
                    {
                        long f = CleanDir(ArcCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog($"Cache Arc : {FormatSize(f)}"));
                    }
                    if (doLogs)
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

                        var cleanEnd = DateTime.Now;
                        var targets = BuildCleanTargetsSummary(doTempWin, doTempUser, doRecycle, doEdge, doChrome, doFirefox, doBrave, doOpera, doVivaldi, doArc, doLogs);
                        try
                        {
                            ServiceContainer.Default.Logger.SaveCleanSession(new CleanSession
                            {
                                StartedAt = cleanStarted,
                                FinishedAt = cleanEnd,
                                TargetsSummary = targets,
                                BytesFreed = freed
                            });
                            ServiceContainer.Default.RequestScanHistoryViewsRefresh();
                        }
                        catch (Exception ex)
                        {
                            AppLogger.Warn("CleanControl", "Enregistrement historique nettoyage", ex);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Nettoyage système", ex);
                AppendLog($"Erreur pendant le nettoyage : {ex.Message}");
            }
            finally
            {
                btnAnalyze.IsEnabled = true;
                if (_analysed)
                    btnCleanNow.IsEnabled = true;
            }
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

        private static string EdgeCachePath() => Path.Combine(LocalApp, @"Microsoft\Edge\User Data\Default\Cache");
        private static string ChromeCachePath() => Path.Combine(LocalApp, @"Google\Chrome\User Data\Default\Cache");
        private static string BraveCachePath() => Path.Combine(LocalApp, @"BraveSoftware\Brave-Browser\User Data\Default\Cache");
        private static string OperaCachePath() => Path.Combine(LocalApp, @"Opera Software\Opera Stable\Cache");
        private static string VivaldiCachePath() => Path.Combine(LocalApp, @"Vivaldi\User Data\Default\Cache");
        private static string ArcCachePath() => Path.Combine(LocalApp, @"Arc\User Data\Default\Cache");
        private static string WindowsLogsPath() => Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"Logs");
        private static string FirefoxCachePath()
        {
            var localProfilesBase = Path.Combine(LocalApp, @"Mozilla\Firefox\Profiles");
            if (!Directory.Exists(localProfilesBase))
                return string.Empty;

            // Priorité : default-release, puis default, puis premier profil local disponible.
            var directories = Directory.EnumerateDirectories(localProfilesBase).ToList();
            string? preferred = directories.FirstOrDefault(d => d.Contains(".default-release", StringComparison.OrdinalIgnoreCase))
                                ?? directories.FirstOrDefault(d => d.Contains(".default", StringComparison.OrdinalIgnoreCase))
                                ?? directories.FirstOrDefault();

            if (!string.IsNullOrEmpty(preferred))
            {
                var cache = Path.Combine(preferred, "cache2");
                if (Directory.Exists(cache))
                    return cache;
            }

            // Repli : lire profiles.ini (Roaming), puis mapper vers le dossier de cache LocalAppData.
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var profilesIni = Path.Combine(roaming, @"Mozilla\Firefox\profiles.ini");
            if (!File.Exists(profilesIni))
                return string.Empty;

            try
            {
                var lines = File.ReadAllLines(profilesIni);
                foreach (var line in lines)
                {
                    if (!line.StartsWith("Path=", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var relativeOrAbsolute = line["Path=".Length..].Trim();
                    if (string.IsNullOrEmpty(relativeOrAbsolute))
                        continue;

                    var profileName = Path.GetFileName(relativeOrAbsolute.TrimEnd('\\', '/'));
                    if (string.IsNullOrEmpty(profileName))
                        continue;

                    var localCandidate = Path.Combine(localProfilesBase, profileName, "cache2");
                    if (Directory.Exists(localCandidate))
                        return localCandidate;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Lecture de profiles.ini Firefox", ex);
            }

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
                    try { total += new FileInfo(f).Length; }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("CleanControl", $"Mesure ignorée : {f}", ex);
                    }
                }
                return total;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", $"Mesure impossible « {path} » : {ex.Message}");
                return 0;
            }
        }

        private static long CleanDir(string path)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return 0;
            long freed = 0;
            try
            {
                foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        long s = new FileInfo(f).Length;
                        File.Delete(f);
                        freed += s;
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("CleanControl", $"Fichier non supprimé : {f}", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", $"Nettoyage incomplet « {path} » : {ex.Message}");
            }
            return freed;
        }

        private static string BuildCleanTargetsSummary(
            bool tempWin, bool tempUser, bool recycle, bool edge, bool chrome, bool firefox, bool brave,
            bool opera, bool vivaldi, bool arc, bool logs)
        {
            var parts = new List<string>(12);
            if (tempWin) parts.Add("Temp Windows");
            if (tempUser) parts.Add("Temp utilisateur");
            if (recycle) parts.Add("Corbeille");
            if (edge) parts.Add("Edge");
            if (chrome) parts.Add("Chrome");
            if (firefox) parts.Add("Firefox");
            if (brave) parts.Add("Brave");
            if (opera) parts.Add("Opera");
            if (vivaldi) parts.Add("Vivaldi");
            if (arc) parts.Add("Arc");
            if (logs) parts.Add("Journaux système");
            return parts.Count == 0 ? "—" : string.Join(", ", parts);
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