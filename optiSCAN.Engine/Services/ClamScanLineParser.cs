// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;
using System.Globalization;
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
            new(@"^([\w\s]+):\s+([\d.]+)", RegexOptions.Compiled);

        internal static bool IsErrorLine(string line)
        {
            var trimmed = line.Trim();
            return trimmed.EndsWith(" ERROR", StringComparison.OrdinalIgnoreCase)
                || trimmed.StartsWith("ERROR:", StringComparison.OrdinalIgnoreCase)
                || trimmed.StartsWith("ERROR ", StringComparison.OrdinalIgnoreCase);
        }

        public static void ProcessLine(
            string line,
            ScanResult result,
            IProgress<ScanProgress>? progress,
            IExclusionSettingsAccessor? exclusions = null)
        {
            if (string.IsNullOrWhiteSpace(line)) return;

            var infectedMatch = InfectedRegex.Match(line);
            if (infectedMatch.Success)
            {
                var filePath = infectedMatch.Groups[1].Value.Trim();
                var virusName = infectedMatch.Groups[2].Value.Trim();

                if ((exclusions ?? new DefaultExclusionSettingsAccessor()).Current.IsFileExcluded(filePath))
                {
                    result.SuppressedDetections++;
                    return;
                }

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; }
                catch (Exception ex) when (!ex.IsFatal())
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

                progress?.Report(ClamProgress(result, ScanPhase.ThreatFound,
                    $"{threat.VirusName} — {filePath}", filePath, threat));
                return;
            }

            if (line.StartsWith("Scanned files:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Data scanned:", StringComparison.OrdinalIgnoreCase))
            {
                ParseStats(line, result);
                progress?.Report(ClamProgress(result, ScanPhase.Scanning,
                    $"{result.FilesScanned:N0} fichiers analysés."));
                return;
            }

            if (ScannedFileLineRegex.IsMatch(line))
            {
                var m = ScannedFileLineRegex.Match(line);
                var scannedPath = m.Success ? m.Groups["path"].Value.Trim() : string.Empty;

                result.FilesScanned++;
                if (ShouldReportScanProgress(result.FilesScanned))
                {
                    progress?.Report(ClamProgress(result, ScanPhase.Scanning,
                        $"{result.FilesScanned:N0} fichiers analysés…",
                        string.IsNullOrEmpty(scannedPath) ? null : scannedPath));
                }
            }
        }

        private static ScanProgress ClamProgress(
            ScanResult result,
            ScanPhase phase,
            string message,
            string? currentFilePath = null,
            ThreatInfo? threat = null)
        {
            var n = result.FilesScanned;
            return new ScanProgress
            {
                Message = message,
                Phase = phase,
                FilesScanned = n,
                ClamFilesScanned = n,
                ThreatsFound = result.ThreatsFound,
                CurrentFilePath = currentFilePath,
                ThreatInfo = threat,
            };
        }

        private static bool ShouldReportScanProgress(int filesScanned)
        {
            if (filesScanned <= 25) return true;
            if (filesScanned <= 500) return filesScanned % 5 == 0;
            return filesScanned % 100 == 0;
        }

        private static void ParseStats(string line, ScanResult result)
        {
            var m = StatsRegex.Match(line);
            if (!m.Success) return;
            var key = m.Groups[1].Value.Trim().ToLowerInvariant();
            var raw = m.Groups[2].Value;
            switch (key)
            {
                case "scanned files":
                    // Valeur hors plage (sortie inattendue) : ignorée plutôt qu'une exception
                    // qui interromprait la lecture de la sortie de clamscan.
                    if (int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var scanned))
                        result.FilesScanned = scanned;
                    break;
                case "data scanned":
                    // clamscan affiche « Data scanned: X.XX MB »
                    if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var mb))
                        result.TotalBytesScanned = (long)(mb * 1024 * 1024);
                    break;
            }
        }
    }
}
