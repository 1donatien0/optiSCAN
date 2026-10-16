// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Localization;
using optiSCAN.Models;
using System.IO;
using System.Security.Cryptography;

namespace optiSCAN.Services
{
    /// <summary>
    /// Sauvegarde optionnelle avant quarantaine et conseils de remédiation (ClamAV = détection, pas réparation binaire).
    /// </summary>
    public static class ThreatRemediationService
    {
        private static readonly string BackupRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN", "SafetyBackups");

        private const long MaxSafetyCopyBytes = 32L * 1024 * 1024;

        /// <summary>Durée de conservation des copies de sécurité.</summary>
        internal static readonly TimeSpan SafetyCopyRetention = TimeSpan.FromDays(30);

        /// <summary>Taille totale au-delà de laquelle les plus anciennes copies sont supprimées.</summary>
        internal const long MaxSafetyCopiesTotalBytes = 256L * 1024 * 1024;

        private const string SafetyCopyExtension = ".optibak";

        public static bool TryCreateSafetyCopy(ThreatInfo threat)
        {
            if (string.IsNullOrWhiteSpace(threat.FilePath) || !File.Exists(threat.FilePath))
                return false;

            try
            {
                // Une seule ouverture : la taille contrôlée est celle du contenu lu (le fichier
                // ne peut pas grossir ni être remplacé entre le contrôle et la lecture).
                byte[] content;
                using (var fs = new FileStream(threat.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length > MaxSafetyCopyBytes)
                        return false;
                    content = new byte[fs.Length];
                    fs.ReadExactly(content);
                    if (fs.ReadByte() != -1)
                        return false;
                }

                return TryCreateSafetyCopy(content);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("ThreatRemediation", "TryCreateSafetyCopy", ex);
                return false;
            }
        }

        /// <summary>Copie de sécurité à partir d'octets déjà lus (quarantaine : pas de seconde ouverture).</summary>
        public static bool TryCreateSafetyCopy(byte[] content) => TryCreateSafetyCopy(content, BackupRoot);

        /// <summary>
        /// Copie chiffrée (DPAPI, compte courant) nommée d'après l'empreinte SHA-256 du contenu :
        /// elle sert de secours à la restauration si le fichier de quarantaine est perdu ou
        /// illisible. Les copies expirées ou en excès sont supprimées à chaque écriture.
        /// </summary>
        internal static bool TryCreateSafetyCopy(byte[] content, string root)
        {
            try
            {
                if (content.Length > MaxSafetyCopyBytes)
                    return false;

                Directory.CreateDirectory(root);
                var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", System.Globalization.CultureInfo.InvariantCulture);
                var hash = Convert.ToHexString(SHA256.HashData(content));
                var dest = Path.Combine(root, $"{stamp}_{hash}_{Guid.NewGuid():N}{SafetyCopyExtension}");
                File.WriteAllBytes(dest, ProtectedData.Protect(content, optionalEntropy: null, DataProtectionScope.CurrentUser));
                AppLogger.Info("ThreatRemediation", $"Copie de sécurité : {PathRedaction.RedactPath(dest)}");
                PurgeSafetyCopies(root);
                return true;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("ThreatRemediation", "TryCreateSafetyCopy", ex);
                return false;
            }
        }

        /// <summary>
        /// Contenu d'une copie de sécurité dont l'empreinte est <paramref name="sha256Hex"/>,
        /// vérifiée après déchiffrement. Null si aucune copie valable.
        /// </summary>
        public static byte[]? TryReadSafetyCopy(string? sha256Hex) => TryReadSafetyCopy(sha256Hex, BackupRoot);

        internal static byte[]? TryReadSafetyCopy(string? sha256Hex, string root)
        {
            if (string.IsNullOrWhiteSpace(sha256Hex) || sha256Hex.Length != 64 || !Directory.Exists(root))
                return null;

            byte[] expected;
            try { expected = Convert.FromHexString(sha256Hex); }
            catch (FormatException) { return null; }

            foreach (var file in FindSafetyCopies(root, sha256Hex))
            {
                try
                {
                    var info = new FileInfo(file);
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > MaxSafetyCopyBytes * 2)
                        continue;
                    var plaintext = ProtectedData.Unprotect(File.ReadAllBytes(file), optionalEntropy: null, DataProtectionScope.CurrentUser);
                    if (CryptographicOperations.FixedTimeEquals(SHA256.HashData(plaintext), expected))
                        return plaintext;
                    CryptographicOperations.ZeroMemory(plaintext);
                }
                catch (Exception ex) when (!ex.IsFatal())
                {
                    AppLogger.Debug("ThreatRemediation", "Copie de sécurité illisible : " + ex.Message);
                }
            }

            return null;
        }

        /// <summary>Supprime les copies d'un contenu (entrée de quarantaine supprimée définitivement).</summary>
        public static int DeleteSafetyCopies(string? sha256Hex) => DeleteSafetyCopies(sha256Hex, BackupRoot);

        internal static int DeleteSafetyCopies(string? sha256Hex, string root)
        {
            if (string.IsNullOrWhiteSpace(sha256Hex) || !Directory.Exists(root))
                return 0;
            var count = 0;
            foreach (var file in FindSafetyCopies(root, sha256Hex))
            {
                try { File.Delete(file); count++; }
                catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Debug("ThreatRemediation", "Suppression copie : " + ex.Message); }
            }
            return count;
        }

        private static IEnumerable<string> FindSafetyCopies(string root, string sha256Hex) =>
            Directory.EnumerateFiles(root, "*_" + sha256Hex.ToUpperInvariant() + "_*" + SafetyCopyExtension)
                .OrderByDescending(f => f, StringComparer.Ordinal);

        /// <summary>
        /// Conservation : copies de plus de <see cref="SafetyCopyRetention"/> supprimées, puis les
        /// plus anciennes tant que le total dépasse <see cref="MaxSafetyCopiesTotalBytes"/>.
        /// Les copies de l'ancien format (sans empreinte, donc jamais restaurables) suivent la même règle.
        /// </summary>
        public static int PurgeSafetyCopies() => PurgeSafetyCopies(BackupRoot);

        internal static int PurgeSafetyCopies(string root, DateTime? nowUtc = null)
        {
            try
            {
                if (!Directory.Exists(root))
                    return 0;
                var now = nowUtc ?? DateTime.UtcNow;
                var files = new DirectoryInfo(root).EnumerateFiles("*" + SafetyCopyExtension)
                    .Where(f => (f.Attributes & FileAttributes.ReparsePoint) == 0)
                    .OrderBy(f => f.LastWriteTimeUtc)
                    .ToList();
                var total = files.Sum(f => f.Length);
                var removed = 0;
                foreach (var file in files)
                {
                    var expired = now - file.LastWriteTimeUtc > SafetyCopyRetention;
                    if (!expired && total <= MaxSafetyCopiesTotalBytes)
                        break;
                    try
                    {
                        var length = file.Length;
                        file.Delete();
                        total -= length;
                        removed++;
                    }
                    catch (Exception ex) when (!ex.IsFatal())
                    {
                        AppLogger.Debug("ThreatRemediation", "Purge copie : " + ex.Message);
                    }
                }

                if (removed > 0)
                    AppLogger.Info("ThreatRemediation", $"{removed} copie(s) de sécurité supprimée(s) (conservation)");
                return removed;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("ThreatRemediation", "PurgeSafetyCopies", ex);
                return 0;
            }
        }

        public static IReadOnlyList<string> GetRemediationSteps(ThreatInfo threat)
        {
            var steps = new List<string>
            {
                LocalizationService.GetString("Remed_Step_Quarantine"),
            };

            if (RiskyFileExtensions.IsExecutable(threat.FilePath))
                steps.Add(LocalizationService.GetString("Remed_Step_NoRun"));

            if (string.Equals(threat.DetectedBy, "YARA", StringComparison.OrdinalIgnoreCase))
                steps.Add(LocalizationService.GetString("Remed_Step_YaraReview"));

            steps.Add(LocalizationService.GetString("Remed_Step_Restore"));
            steps.Add(LocalizationService.GetString("Remed_Step_NoRepairNote"));
            return steps;
        }
    }
}
