using optiSCAN.Localization;
using System.Runtime.InteropServices;

namespace optiSCAN.Services;

/// <summary>Moteur d'analyse et de nettoyage (temporaires, caches navigateurs, corbeille).</summary>
public static class CleanEngine
{
    public readonly struct CleanSelection
    {
        public bool TempWin { get; init; }
        public bool TempUser { get; init; }
        public bool Recycle { get; init; }
        public bool Logs { get; init; }
        public bool Edge { get; init; }
        public bool Chrome { get; init; }
        public bool Firefox { get; init; }
        public bool Brave { get; init; }
        public bool Opera { get; init; }
        public bool Vivaldi { get; init; }
        public bool Arc { get; init; }
        public bool WUCache { get; init; }
        public bool Dns { get; init; }
        public bool History { get; init; }

        public bool AnySystem => TempWin || TempUser || Recycle || Logs || WUCache || Dns;
        public bool AnyBrowser => Edge || Chrome || Firefox || Brave || Opera || Vivaldi || Arc;
        public bool HasSelection => AnySystem || AnyBrowser;
    }

    public sealed record AnalyzeResult(
        long SystemBytes,
        long BrowserBytes,
        IReadOnlyList<string> LogLines,
        bool CanClean,
        bool ShowEmptyState);

    public sealed record CleanResult(long BytesFreed, IReadOnlyList<string> LogLines);

    public sealed record CleanupCatalogEntry(
        string Id,
        string NameKey,
        string? DetailsKey,
        bool DefaultSelected,
        bool IsBrowser);

    public static IReadOnlyList<CleanupCatalogEntry> GetCatalog() =>
    [
        new("TempWin", "Clean_TempWinCb", null, true, false),
        new("TempUser", "Clean_TempUserCb", null, true, false),
        new("Recycle", "Clean_RecycleCb", null, true, false),
        new("Logs", "Clean_LogsCb", null, false, false),
        new("WUCache", "Clean_WUCacheCb", null, false, false),
        new("Dns", "Clean_DnsCb", null, false, false),
        new("Edge", "Clean_Edge", "Clean_BrowserSub", true, true),
        new("Chrome", "Clean_Chrome", "Clean_BrowserSub", true, true),
        new("Firefox", "Clean_Firefox", "Clean_BrowserSub", true, true),
        new("Brave", "Clean_Brave", "Clean_BrowserSub", false, true),
        new("Opera", "Clean_Opera", "Clean_BrowserSub", false, true),
        new("Vivaldi", "Clean_Vivaldi", "Clean_BrowserSub", false, true),
        new("Arc", "Clean_Arc", "Clean_BrowserSub", false, true),
        new("History", "Clean_HistoryCb", "Clean_HistoryTooltip", false, true),
    ];

    public static CleanSelection SelectionFromIds(IEnumerable<string> selectedIds)
    {
        var set = new HashSet<string>(selectedIds, StringComparer.OrdinalIgnoreCase);
        return new CleanSelection
        {
            TempWin = set.Contains("TempWin"),
            TempUser = set.Contains("TempUser"),
            Recycle = set.Contains("Recycle"),
            Logs = set.Contains("Logs"),
            Edge = set.Contains("Edge"),
            Chrome = set.Contains("Chrome"),
            Firefox = set.Contains("Firefox"),
            Brave = set.Contains("Brave"),
            Opera = set.Contains("Opera"),
            Vivaldi = set.Contains("Vivaldi"),
            Arc = set.Contains("Arc"),
            WUCache = set.Contains("WUCache"),
            Dns = set.Contains("Dns"),
            History = set.Contains("History"),
        };
    }

    private sealed record CleanTarget(
        bool IsSelected,
        string AnalyzeLogKey,
        string CleanFreedKey,
        string? BrowserNameKey,
        Func<string> GetPath,
        bool IsBrowser = false,
        bool IsRecycleBin = false);

    public static AnalyzeResult Analyze(CleanSelection sel)
    {
        var lines = new List<string>();
        long sysTotal = 0;
        long browserTotal = 0;

        foreach (var target in GetTargets(sel).Where(t => t.IsSelected))
        {
            if (target.IsRecycleBin)
                continue;

            long size = MeasureDir(target.GetPath());
            if (target.IsBrowser)
                browserTotal += size;
            else
                sysTotal += size;

            if (size > 0 || target.IsBrowser)
                lines.Add(LocalizationService.Format(target.AnalyzeLogKey, FormatSize(size)));
        }

        if (sel.WUCache)
        {
            long wuSize = MeasureDir(WindowsUpdateCachePath());
            sysTotal += wuSize;
            lines.Add(LocalizationService.Format("Clean_LogLineWU", FormatSize(wuSize)));
        }

        if (sel.History)
        {
            long historySize = MeasureFiles(HistoryTargets(sel));
            browserTotal += historySize;
            lines.Add(LocalizationService.Format("Clean_LogLineHistory", FormatSize(historySize)));
            if (sel.Firefox)
                lines.Add(LocalizationService.GetString("Clean_LogHistoryFirefox"));
        }

        long total = sysTotal + browserTotal;
        lines.Add("─────────────────────────");
        lines.Add(LocalizationService.Format("Clean_LogTotal", FormatSize(total)));
        lines.Add(LocalizationService.GetString("Clean_LogAnalyzeEnd"));

        return new AnalyzeResult(
            sysTotal,
            browserTotal,
            lines,
            CanClean: total > 0 || sel.Dns || sel.Recycle,
            ShowEmptyState: total == 0 && !sel.Dns && !sel.Recycle);
    }

    public static CleanResult Clean(CleanSelection sel)
    {
        var lines = new List<string>();
        long freed = 0;

        foreach (var target in GetTargets(sel).Where(t => t.IsSelected))
        {
            if (target.IsRecycleBin)
            {
                SHEmptyRecycleBin(IntPtr.Zero, null, 0x0007);
                lines.Add(LocalizationService.GetString("Clean_LogRecycleEmptied"));
                continue;
            }

            long f = CleanDir(target.GetPath());
            freed += f;

            if (f > 0 || target.IsBrowser)
            {
                lines.Add(target.IsBrowser && target.BrowserNameKey != null
                    ? LocalizationService.Format(
                        target.CleanFreedKey,
                        LocalizationService.GetString(target.BrowserNameKey),
                        FormatSize(f))
                    : LocalizationService.Format(target.CleanFreedKey, FormatSize(f)));
            }
        }

        if (sel.WUCache)
        {
            // Nécessite l'arrêt du service Windows Update → script administrateur
            // (une invite UAC) ; taille mesurée avant/après.
            long before = MeasureDir(WindowsUpdateCachePath());
            bool ok = SystemTweaksService.RunElevatedBatch(
                SystemTweaksService.ElevatedWindowsUpdateCacheCommands(),
                waitForExit: true);
            if (ok)
            {
                long after = MeasureDir(WindowsUpdateCachePath());
                long f = Math.Max(0, before - after);
                freed += f;
                lines.Add(LocalizationService.Format("Clean_LogFreedWU", FormatSize(f)));
            }
            else
            {
                lines.Add(LocalizationService.GetString("Clean_LogWUDenied"));
            }
        }

        if (sel.Dns && SystemTweaksService.FlushDnsCache())
            lines.Add(LocalizationService.GetString("Clean_LogDnsFlushed"));

        if (sel.History)
        {
            var (f, locked) = CleanFiles(HistoryTargets(sel));
            freed += f;
            lines.Add(LocalizationService.Format("Clean_LogFreedHistory", FormatSize(f)));
            if (locked > 0)
                lines.Add(LocalizationService.Format("Clean_LogHistoryLocked", locked));
            if (sel.Firefox)
                lines.Add(LocalizationService.GetString("Clean_LogHistoryFirefox"));
        }

        lines.Add("─────────────────────────");
        lines.Add(LocalizationService.Format("Clean_LogFreedTotal", FormatSize(freed)));
        lines.Add(LocalizationService.GetString("Clean_LogCleanEnd"));

        return new CleanResult(freed, lines);
    }

    public static string BuildTargetsSummary(CleanSelection sel)
    {
        var parts = new List<string>(14);
        if (sel.TempWin) parts.Add(LocalizationService.GetString("Clean_TempWinCb"));
        if (sel.TempUser) parts.Add(LocalizationService.GetString("Clean_TempUserCb"));
        if (sel.Recycle) parts.Add(LocalizationService.GetString("Clean_RecycleCb"));
        if (sel.Logs) parts.Add(LocalizationService.GetString("Clean_LogsCb"));
        if (sel.Edge) parts.Add(LocalizationService.GetString("Clean_Edge"));
        if (sel.Chrome) parts.Add(LocalizationService.GetString("Clean_Chrome"));
        if (sel.Firefox) parts.Add(LocalizationService.GetString("Clean_Firefox"));
        if (sel.Brave) parts.Add(LocalizationService.GetString("Clean_Brave"));
        if (sel.Opera) parts.Add(LocalizationService.GetString("Clean_Opera"));
        if (sel.Vivaldi) parts.Add(LocalizationService.GetString("Clean_Vivaldi"));
        if (sel.Arc) parts.Add(LocalizationService.GetString("Clean_Arc"));
        if (sel.WUCache) parts.Add(LocalizationService.GetString("Clean_WUCacheCb"));
        if (sel.Dns) parts.Add(LocalizationService.GetString("Clean_DnsCb"));
        if (sel.History) parts.Add(LocalizationService.GetString("Clean_HistoryCb"));
        return parts.Count == 0 ? "—" : string.Join(", ", parts);
    }

    public static bool IsHintLog(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return true;
        var t = text.TrimStart();
        return t.StartsWith("Cliquez", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Click", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<CleanTarget> GetTargets(CleanSelection sel) =>
    [
        new(sel.TempWin, "Clean_LogLineTempWin", "Clean_LogFreedTempWin", null,
            () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")),
        new(sel.TempUser, "Clean_LogLineTempUser", "Clean_LogFreedTempUser", null, Path.GetTempPath),
        new(sel.Logs, "Clean_LogLineLogs", "Clean_LogFreedLogs", null, WindowsLogsPath),
        new(sel.Edge, "Clean_LogLineEdge", "Clean_LogFreedCache", "Clean_Browser_Edge", EdgeCachePath, IsBrowser: true),
        new(sel.Chrome, "Clean_LogLineChrome", "Clean_LogFreedCache", "Clean_Browser_Chrome", ChromeCachePath, IsBrowser: true),
        new(sel.Firefox, "Clean_LogLineFirefox", "Clean_LogFreedCache", "Clean_Browser_Firefox", FirefoxCachePath, IsBrowser: true),
        new(sel.Brave, "Clean_LogLineBrave", "Clean_LogFreedCache", "Clean_Browser_Brave", BraveCachePath, IsBrowser: true),
        new(sel.Opera, "Clean_LogLineOpera", "Clean_LogFreedCache", "Clean_Browser_Opera", OperaCachePath, IsBrowser: true),
        new(sel.Vivaldi, "Clean_LogLineVivaldi", "Clean_LogFreedCache", "Clean_Browser_Vivaldi", VivaldiCachePath, IsBrowser: true),
        new(sel.Arc, "Clean_LogLineArc", "Clean_LogFreedCache", "Clean_Browser_Arc", ArcCachePath, IsBrowser: true),
        new(sel.Recycle, string.Empty, string.Empty, null, () => string.Empty, IsRecycleBin: true),
    ];

    private static string LocalApp => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static string EdgeCachePath() => Path.Combine(LocalApp, @"Microsoft\Edge\User Data\Default\Cache");
    private static string ChromeCachePath() => Path.Combine(LocalApp, @"Google\Chrome\User Data\Default\Cache");
    private static string BraveCachePath() => Path.Combine(LocalApp, @"BraveSoftware\Brave-Browser\User Data\Default\Cache");
    private static string OperaCachePath() => Path.Combine(LocalApp, @"Opera Software\Opera Stable\Cache");
    private static string VivaldiCachePath() => Path.Combine(LocalApp, @"Vivaldi\User Data\Default\Cache");
    private static string ArcCachePath() => Path.Combine(LocalApp, @"Arc\User Data\Default\Cache");
    private static string WindowsLogsPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs");

    private static string WindowsUpdateCachePath() => Path.Combine(
        Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
        @"SoftwareDistribution\Download");

    // Historique de navigation (navigateurs Chromium uniquement) : fichiers SQLite
    // « History » du dossier profil (parent du Cache). Firefox est exclu :
    // places.sqlite contient aussi les favoris.
    private static readonly string[] ChromiumHistoryFileNames =
    {
        "History", "History-journal", "Visited Links",
    };

    private static IEnumerable<string> ChromiumHistoryFiles(string cachePath)
    {
        if (string.IsNullOrEmpty(cachePath))
            yield break;
        var profileDir = Path.GetDirectoryName(cachePath);
        if (string.IsNullOrEmpty(profileDir))
            yield break;
        foreach (var name in ChromiumHistoryFileNames)
            yield return Path.Combine(profileDir, name);
    }

    private static List<string> HistoryTargets(CleanSelection sel)
    {
        var files = new List<string>();
        if (sel.Edge) files.AddRange(ChromiumHistoryFiles(EdgeCachePath()));
        if (sel.Chrome) files.AddRange(ChromiumHistoryFiles(ChromeCachePath()));
        if (sel.Brave) files.AddRange(ChromiumHistoryFiles(BraveCachePath()));
        if (sel.Opera) files.AddRange(ChromiumHistoryFiles(OperaCachePath()));
        if (sel.Vivaldi) files.AddRange(ChromiumHistoryFiles(VivaldiCachePath()));
        if (sel.Arc) files.AddRange(ChromiumHistoryFiles(ArcCachePath()));
        return files;
    }

    private static long MeasureFiles(IEnumerable<string> paths)
    {
        long total = 0;
        foreach (var p in paths)
        {
            try
            {
                if (File.Exists(p))
                    total += new FileInfo(p).Length;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanEngine", $"Mesure ignorée : {p}", ex);
            }
        }
        return total;
    }

    /// <summary>Supprime les fichiers donnés. Renvoie (octets libérés, nb verrouillés/échoués).</summary>
    private static (long Freed, int Locked) CleanFiles(IEnumerable<string> paths)
    {
        long freed = 0;
        int locked = 0;
        foreach (var p in paths)
        {
            try
            {
                if (!File.Exists(p))
                    continue;
                long size = new FileInfo(p).Length;
                File.Delete(p);
                freed += size;
            }
            catch (Exception ex)
            {
                locked++;
                AppLogger.Warn("CleanEngine", $"Fichier non supprimé : {p}", ex);
            }
        }
        return (freed, locked);
    }

    private static string FirefoxCachePath()
    {
        var localProfilesBase = Path.Combine(LocalApp, @"Mozilla\Firefox\Profiles");
        if (!Directory.Exists(localProfilesBase))
            return string.Empty;

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

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var profilesIni = Path.Combine(roaming, @"Mozilla\Firefox\profiles.ini");
        if (!File.Exists(profilesIni))
            return string.Empty;

        try
        {
            foreach (var line in File.ReadAllLines(profilesIni))
            {
                if (!line.StartsWith("Path=", StringComparison.OrdinalIgnoreCase))
                    continue;
                var relativeOrAbsolute = line["Path=".Length..].Trim();
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
            AppLogger.Warn("CleanEngine", "Firefox profiles.ini", ex);
        }

        return string.Empty;
    }

    private static long MeasureDir(string path)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            return 0;
        try
        {
            long total = 0;
            foreach (var file in new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories))
            {
                try { total += file.Length; }
                catch { /* fichier verrouillé */ }
            }
            return total;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("CleanEngine", $"MeasureDir {path}", ex);
            return 0;
        }
    }

    private static long CleanDir(string path)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            return 0;
        long freed = 0;
        try
        {
            foreach (var file in new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories))
            {
                try
                {
                    long s = file.Length;
                    file.Delete();
                    freed += s;
                }
                catch { /* fichier en cours d'utilisation */ }
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("CleanEngine", $"CleanDir {path}", ex);
        }
        return freed;
    }

    private static string FormatSize(long bytes) => ByteSizeFormat.Format(bytes);

    [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
}
