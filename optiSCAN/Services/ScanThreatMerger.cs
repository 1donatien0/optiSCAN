using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Fusionne les menaces ClamAV et YARA dans un <see cref="ScanResult"/> unique.
    /// </summary>
    internal static class ScanThreatMerger
    {
        /// <summary>
        /// Fusionne deux résultats moteur. Plusieurs signatures ClamAV ou règles YARA
        /// pour le même fichier sont agrégées dans <see cref="ThreatInfo.VirusName"/>.
        /// </summary>
        public static ScanResult Merge(ScanType type, string target, ScanResult clamResult, ScanResult yaraResult)
        {
            var merged = new ScanResult
            {
                Type = type,
                TargetPath = target,
                StartedAt = clamResult.StartedAt < yaraResult.StartedAt ? clamResult.StartedAt : yaraResult.StartedAt,
                FinishedAt = DateTime.Now,
                FilesScanned = Math.Max(clamResult.FilesScanned, yaraResult.FilesScanned),
                FilesSkipped = clamResult.FilesSkipped,
                TotalBytesScanned = clamResult.TotalBytesScanned,
                Status = (clamResult.Status == ScanStatus.Cancelled || yaraResult.Status == ScanStatus.Cancelled)
                    ? ScanStatus.Cancelled
                    : ScanStatus.Completed
            };

            var excl = ExclusionSettings.Current;
            var clamThreats = clamResult.Threats.Where(t => !excl.IsFileExcluded(t.FilePath)).ToList();
            var yaraThreats = yaraResult.Threats.Where(t => !excl.IsFileExcluded(t.FilePath)).ToList();

            var clamByPath = AggregateClamByPath(clamThreats);
            merged.Threats.AddRange(clamByPath.Values);

            var yaraNamesByPath = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var seenYaraTriples = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var yaraT in yaraThreats)
            {
                var triple = $"{yaraT.FilePath}|{yaraT.VirusName}";
                if (!seenYaraTriples.Add(triple))
                    continue;

                if (clamByPath.TryGetValue(yaraT.FilePath, out var existing))
                {
                    if (!yaraNamesByPath.TryGetValue(yaraT.FilePath, out var names))
                        yaraNamesByPath[yaraT.FilePath] = names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    names.Add(yaraT.VirusName);
                    existing.DetectedBy = "ClamAV+YARA";
                }
                else
                {
                    merged.Threats.Add(yaraT);
                }
            }

            foreach (var kv in yaraNamesByPath)
            {
                var t = clamByPath[kv.Key];
                var sortedRules = string.Join(",", kv.Value.OrderBy(s => s, StringComparer.Ordinal));
                if (!t.VirusName.Contains(sortedRules, StringComparison.OrdinalIgnoreCase))
                    t.VirusName += $" / YARA:{sortedRules}";
            }

            return merged;
        }

        /// <summary>
        /// Une entrée ClamAV par chemin ; plusieurs noms de virus → libellé joint par « / ».
        /// </summary>
        internal static Dictionary<string, ThreatInfo> AggregateClamByPath(IEnumerable<ThreatInfo> clamThreats)
        {
            var byPath = new Dictionary<string, ThreatInfo>(StringComparer.OrdinalIgnoreCase);
            var namesByPath = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var t in clamThreats)
            {
                if (!byPath.TryGetValue(t.FilePath, out var existing))
                {
                    byPath[t.FilePath] = t;
                    namesByPath[t.FilePath] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { t.VirusName };
                    continue;
                }

                namesByPath[t.FilePath].Add(t.VirusName);
                if (t.DetectedAt < existing.DetectedAt)
                    existing.DetectedAt = t.DetectedAt;
            }

            foreach (var kv in namesByPath)
            {
                if (kv.Value.Count <= 1) continue;
                byPath[kv.Key].VirusName = string.Join(" / ", kv.Value.OrderBy(s => s, StringComparer.Ordinal));
            }

            return byPath;
        }
    }
}
