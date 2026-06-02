using optiSCAN.Models;
using System.IO;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Parse les lignes de sortie clamscan / clamd (format identique).
    /// </summary>
    internal static class ClamScanLineParser
    {
        private static readonly Regex InfectedRegex =
            new(@"^(.+):\s+(.+)\s+FOUND\s*$", RegexOptions.Compiled);

        private static readonly Regex ScannedFileLineRegex =
            new(@"^(?<path>.+):\s+(?<verdict>OK|FOUND|Empty file|Excluded|Symbolic link)\s*$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex StatsRegex =
            new(@"^([\w\s]+):\s+(\d+)", RegexOptions.Compiled);

        public static void ProcessLine(string line, ScanResult result, IProgress<ScanProgress>? progress)
        {
            if (string.IsNullOrWhiteSpace(line)) return;

            var infectedMatch = InfectedRegex.Match(line);
            if (infectedMatch.Success)
            {
                var filePath = infectedMatch.Groups[1].Value.Trim();
                var virusName = infectedMatch.Groups[2].Value.Trim();

                if (ExclusionSettings.Current.IsFileExcluded(filePath))
                    return;

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; }
                catch (Exception ex)
                {
                    AppLogger.Warn("ClamScanLineParser", $"Taille fichier indisponible : {filePath}", ex);
                }

                var threat = new ThreatInfo
                {
                    FilePath = filePath,
                    VirusName = virusName,
                    DetectedAt = DateTime.Now,
                    Status = ThreatStatus.Detected,
                    FileSize = fileSize,
                    DetectedBy = "ClamAV",
                };
                result.Threats.Add(threat);

                progress?.Report(new ScanProgress
                {
                    Message = $"{threat.VirusName} — {filePath}",
                    Phase = ScanPhase.ThreatFound,
                    ThreatInfo = threat,
                    FilesScanned = result.FilesScanned,
                    ThreatsFound = result.ThreatsFound,
                    CurrentFilePath = filePath,
                });
                return;
            }

            if (line.StartsWith("Scanned files:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Data scanned:", StringComparison.OrdinalIgnoreCase))
            {
                ParseStats(line, result);
                progress?.Report(new ScanProgress
                {
                    Message = $"{result.FilesScanned:N0} fichiers analysés.",
                    Phase = ScanPhase.Scanning,
                    FilesScanned = result.FilesScanned,
                    ThreatsFound = result.ThreatsFound,
                });
                return;
            }

            if (ScannedFileLineRegex.IsMatch(line))
            {
                var m = ScannedFileLineRegex.Match(line);
                var scannedPath = m.Success ? m.Groups["path"].Value.Trim() : string.Empty;

                result.FilesScanned++;
                if (ShouldReportScanProgress(result.FilesScanned))
                {
                    progress?.Report(new ScanProgress
                    {
                        Message = $"{result.FilesScanned:N0} fichiers analysés…",
                        Phase = ScanPhase.Scanning,
                        FilesScanned = result.FilesScanned,
                        ThreatsFound = result.ThreatsFound,
                        CurrentFilePath = string.IsNullOrEmpty(scannedPath) ? null : scannedPath,
                    });
                }
            }
        }

        private static bool ShouldReportScanProgress(int filesScanned)
        {
            if (filesScanned <= 25) return true;
            if (filesScanned % 5 == 0) return true;
            return filesScanned % 100 == 0;
        }

        private static void ParseStats(string line, ScanResult result)
        {
            var m = StatsRegex.Match(line);
            if (!m.Success) return;
            var key = m.Groups[1].Value.Trim().ToLowerInvariant();
            var value = long.Parse(m.Groups[2].Value);
            switch (key)
            {
                case "scanned files":
                    result.FilesScanned = (int)value;
                    break;
                case "data scanned":
                    result.TotalBytesScanned = value * 1024;
                    break;
            }
        }
    }
}
