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
            catch (Exception ex)
            {
                AppLogger.Warn("ThreatRemediation", "TryCreateSafetyCopy", ex);
                return false;
            }
        }

        /// <summary>Copie de sécurité à partir d'octets déjà lus (quarantaine : pas de seconde ouverture).</summary>
        public static bool TryCreateSafetyCopy(byte[] content)
        {
            try
            {
                if (content.Length > MaxSafetyCopyBytes)
                    return false;

                Directory.CreateDirectory(BackupRoot);
                var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                var dest = Path.Combine(BackupRoot, $"{stamp}_{Guid.NewGuid():N}.optibak");
                File.WriteAllBytes(dest, ProtectedData.Protect(content, optionalEntropy: null, DataProtectionScope.CurrentUser));
                AppLogger.Info("ThreatRemediation", $"Copie de sécurité : {PathRedaction.RedactPath(dest)}");
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThreatRemediation", "TryCreateSafetyCopy", ex);
                return false;
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
