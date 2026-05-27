using optiSCAN.Models;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Calcule un score de risque pour une menace détectée.
    /// Classification : Informationnel / Mineur / Majeur / Critique
    /// </summary>
    public static class RiskScoringService
    {
        // Mots-clés associés à des niveaux de risque
        private static readonly Dictionary<string, RiskLevel> KeywordRiskMap = new(StringComparer.OrdinalIgnoreCase)
        {
            // CRITIQUE
            { "ransom",          RiskLevel.Critical },
            { "ransomware",      RiskLevel.Critical },
            { "locky",           RiskLevel.Critical },
            { "wannacry",        RiskLevel.Critical },
            { "notpetya",        RiskLevel.Critical },
            { "rootkit",         RiskLevel.Critical },
            { "bootkit",         RiskLevel.Critical },
            { "backdoor",        RiskLevel.Critical },
            { "trojan.ransom",   RiskLevel.Critical },
            { "malware.ransom",  RiskLevel.Critical },
            { "worm.win32",      RiskLevel.Critical },

            // MAJEUR
            { "trojan",          RiskLevel.Major },
            { "worm",            RiskLevel.Major },
            { "spy",             RiskLevel.Major },
            { "spyware",         RiskLevel.Major },
            { "keylog",          RiskLevel.Major },
            { "keylogger",       RiskLevel.Major },
            { "downloader",      RiskLevel.Major },
            { "dropper",         RiskLevel.Major },
            { "infostealer",     RiskLevel.Major },
            { "banker",          RiskLevel.Major },

            // MINEUR
            { "adware",          RiskLevel.Minor },
            { "pup",             RiskLevel.Minor },
            { "pua",             RiskLevel.Minor },
            { "hacktool",        RiskLevel.Minor },
            { "riskware",        RiskLevel.Minor },
            { "potentially",     RiskLevel.Minor },
            { "unsafe",          RiskLevel.Minor },

            // INFORMATIONNEL
            { "suspicious",      RiskLevel.Informational },
            { "detected",        RiskLevel.Informational },
        };

        // Extensions exécutables à risque élevé
        private static readonly HashSet<string> HighRiskExtensions = new(
            new[] { ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".jar", ".msi" },
            StringComparer.OrdinalIgnoreCase);

        // Documents Office avec macros
        private static readonly HashSet<string> MacroExtensions = new(
            new[] { ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".ppam" },
            StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Évalue complètement le niveau de risque d'une menace
        /// </summary>
        public static RiskAssessment Assess(ThreatInfo threat)
        {
            var score = 0;
            var reasons = new List<string>();

            // 1. Analyse du nom du virus
            var (level, reason) = AnalyzeVirusName(threat.VirusName);
            score += GetScore(level);
            reasons.Add(reason);

            // 2. Analyse du fichier
            var fileLevel = AnalyzeFilePath(threat.FilePath);
            score += GetScore(fileLevel);
            reasons.Add($"Fichier : {GetFileRiskReason(threat.FilePath, fileLevel)}");

            // 3. Double détection (ClamAV + YARA)
            if (!string.IsNullOrEmpty(threat.DetectedBy) && threat.DetectedBy.Contains('+'))
            {
                score += 20;
                reasons.Add("Détection corroborée");
            }

            // 4. Taille du fichier
            if (threat.FileSize > 0 && threat.FileSize < 1024 * 1024) // < 1 Mo
            {
                score += 10;
                reasons.Add("Petite taille → potentiel payload malveillant");
            }
            else if (threat.FileSize > 50 * 1024 * 1024) // > 50 Mo
            {
                score -= 10;
                reasons.Add("Grand fichier → risque plus faible");
            }

            var finalLevel = GetRiskLevelFromScore(score);

            return new RiskAssessment
            {
                Score = score,
                Level = finalLevel,
                Severity = GetSeverityString(finalLevel),
                Color = GetSeverityColor(finalLevel),
                IconKind = GetSeverityIconKind(finalLevel),
                Recommendation = GetRecommendation(finalLevel, threat),
                Reasons = reasons
            };
        }

        /// <summary>
        /// Évalue une liste de menaces et retourne l'évaluation la plus sévère.
        /// Utilisé dans les rapports où plusieurs menaces peuvent être présentes.
        /// </summary>
        public static RiskAssessment AssessAll(IEnumerable<ThreatInfo> threats)
        {
            RiskAssessment? worst = null;
            foreach (var threat in threats)
            {
                var assessment = Assess(threat);
                if (worst == null || assessment.Score > worst.Score)
                    worst = assessment;
            }
            return worst ?? new RiskAssessment
            {
                Severity = "AUCUNE MENACE",
                Color = "#27AE60",
                IconKind = UiIconKinds.Success,
                Recommendation = "Système sain."
            };
        }

        /// <summary>
        /// Version simplifiée pour affichage rapide (badge de sévérité)
        /// </summary>
        public static string GetSeverityLevel(ThreatInfo threat)
        {
            var (level, _) = AnalyzeVirusName(threat.VirusName);
            return GetSeverityString(level);
        }

        // ── Analyse interne ──────────────────────────────────────────────────────

        /// <summary>
        /// Normalise un nom de menace ou un mot-clé pour la comparaison :
        /// remplace '_' et '.' par un espace afin que "trojan.ransom" matche
        /// "win_trojan_ransom_xyz" et réciproquement.
        /// </summary>
        private static string NormalizeForMatch(string s)
            => s.Replace('_', ' ').Replace('.', ' ');

        private static (RiskLevel, string) AnalyzeVirusName(string virusName)
        {
            if (string.IsNullOrEmpty(virusName))
                return (RiskLevel.Informational, "Nom de menace inconnu");

            var normalizedName = NormalizeForMatch(virusName);

            foreach (var kvp in KeywordRiskMap)
            {
                // Correspondance directe (ex. ClamAV : "Trojan.GenericKD")
                if (virusName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    return (kvp.Value, $"Mot-clé '{kvp.Key}' détecté dans le nom");

                // Correspondance normalisée (ex. YARA : "win_trojan_ransom_xyz"
                // → "win trojan ransom xyz" contient "trojan ransom")
                var normalizedKey = NormalizeForMatch(kvp.Key);
                if (normalizedName.Contains(normalizedKey, StringComparison.OrdinalIgnoreCase))
                    return (kvp.Value, $"Mot-clé '{kvp.Key}' détecté dans le nom (normalisé)");
            }

            return (RiskLevel.Minor, "Menace générique");
        }

        private static RiskLevel AnalyzeFilePath(string filePath)
        {
            var ext = Path.GetExtension(filePath);

            if (filePath.Contains(@"\Windows\System32\") || filePath.Contains(@"\Windows\SysWOW64\"))
                return RiskLevel.Critical;

            if (HighRiskExtensions.Contains(ext) || MacroExtensions.Contains(ext))
                return RiskLevel.Major;

            if (filePath.Contains(@"\Temp\") || filePath.Contains(@"\AppData\Local\Temp"))
                return RiskLevel.Minor;

            return RiskLevel.Informational;
        }

        private static string GetFileRiskReason(string filePath, RiskLevel level)
        {
            var ext = Path.GetExtension(filePath);

            if (filePath.Contains(@"\Windows\System32\"))
                return "Fichier système critique → risque critique";

            if (HighRiskExtensions.Contains(ext))
                return $"Extension exécutable ({ext}) → risque majeur";

            if (MacroExtensions.Contains(ext))
                return $"Document avec macros ({ext}) → risque majeur";

            if (filePath.Contains(@"\Temp\"))
                return "Fichier temporaire → risque modéré";

            return "Fichier standard";
        }

        private static int GetScore(RiskLevel level) => level switch
        {
            RiskLevel.Critical => 60,
            RiskLevel.Major => 40,
            RiskLevel.Minor => 20,
            RiskLevel.Informational => 5,
            _ => 10
        };

        private static RiskLevel GetRiskLevelFromScore(int score) => score switch
        {
            >= 80 => RiskLevel.Critical,
            >= 50 => RiskLevel.Major,
            >= 25 => RiskLevel.Minor,
            _ => RiskLevel.Informational
        };

        // ── Helpers d'affichage ──────────────────────────────────────────────────

        private static string GetSeverityString(RiskLevel level) => level switch
        {
            RiskLevel.Critical => "CRITIQUE",
            RiskLevel.Major => "MAJEUR",
            RiskLevel.Minor => "MINEUR",
            _ => "INFORMATIONNEL"
        };

        private static string GetSeverityColor(RiskLevel level) => level switch
        {
            RiskLevel.Critical => "#C0392B",
            RiskLevel.Major => "#E67E22",
            RiskLevel.Minor => "#F1C40F",
            _ => "#27AE60"
        };

        private static string GetSeverityIconKind(RiskLevel level) => UiIconKinds.ForRiskLevel(level);

        private static string GetRecommendation(RiskLevel level, ThreatInfo threat) => level switch
        {
            RiskLevel.Critical =>
                $"ACTION IMMÉDIATE REQUISE : Mettez en quarantaine ou supprimez {threat.FileName} immédiatement.",
            RiskLevel.Major =>
                $"Action recommandée : Mettez en quarantaine {threat.FileName} dès que possible.",
            RiskLevel.Minor =>
                $"Action facultative : Surveillez {threat.FileName} ou mettez-le en quarantaine par précaution.",
            _ =>
                $"Information : {threat.VirusName} — aucune action immédiate requise."
        };
    }

    // ── Modèles ──────────────────────────────────────────────────────────────────

    public enum RiskLevel
    {
        Informational,
        Minor,
        Major,
        Critical
    }

    public class RiskAssessment
    {
        public int Score { get; set; }
        public RiskLevel Level { get; set; }
        public string Severity { get; set; } = string.Empty;
        public string Color { get; set; } = string.Empty;
        /// <summary>Nom <see cref="MaterialDesignThemes.Wpf.PackIconKind"/> (ex. Alert, CheckCircle).</summary>
        public string IconKind { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public List<string> Reasons { get; set; } = new();
    }
}
