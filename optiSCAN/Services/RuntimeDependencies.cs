using System.IO;
using System.Text;

namespace optiSCAN.Services
{
    /// <summary>
    /// Vérifie la présence des binaires et ressources embarqués requis au runtime
    /// (non versionnés dans git — fournis par publish ou installateur).
    /// </summary>
    public static class RuntimeDependencies
    {
        public sealed class DependencyStatus
        {
            public string Name { get; init; } = string.Empty;
            public bool IsReady { get; init; }
            public string ExpectedPath { get; init; } = string.Empty;
            public string Detail { get; init; } = string.Empty;
        }

        public sealed class Report
        {
            public IReadOnlyList<DependencyStatus> Items { get; init; } = Array.Empty<DependencyStatus>();
            public bool IsFullyReady => Items.Count > 0 && Items.All(i => i.IsReady);
            public bool IsClamAvReady => Items.FirstOrDefault(i => i.Name == "ClamAV")?.IsReady == true;
            public bool IsYaraReady => Items.FirstOrDefault(i => i.Name == "YARA")?.IsReady == true;

            public string BuildSummaryLine()
            {
                if (IsFullyReady)
                    return "Moteurs ClamAV et YARA prêts.";
                var missing = Items.Where(i => !i.IsReady).Select(i => i.Name).ToList();
                return missing.Count == 0
                    ? "Dépendances runtime incomplètes."
                    : $"Manquant : {string.Join(", ", missing)}.";
            }

            public string BuildDetailedMessage()
            {
                var sb = new StringBuilder();
                sb.AppendLine($"Répertoire d'exécution : {AppInstallPaths.GetInstallRoot()}");
                sb.AppendLine();
                foreach (var item in Items)
                {
                    sb.AppendLine(item.IsReady ? UiLogText.ReadyLine(item.Name) : UiLogText.MissingLine(item.Name));
                    sb.AppendLine($"  Attendu : {item.ExpectedPath}");
                    if (!string.IsNullOrWhiteSpace(item.Detail))
                        sb.AppendLine($"  {item.Detail}");
                    sb.AppendLine();
                }
                if (!IsFullyReady)
                {
                    sb.AppendLine("En développement : copiez clamav/x64 et yara/ sous optiSCAN/,");
                    sb.AppendLine("ou exécutez : .\\scripts\\verify-runtime-deps.ps1");
                    sb.AppendLine("Voir README § 3 (ClamAV) et publication § 8.");
                }
                return sb.ToString().TrimEnd();
            }
        }

        public static Report Evaluate()
        {
            var baseDir = AppInstallPaths.GetInstallRoot();
            var arch = Environment.Is64BitProcess ? "x64" : "x86";
            var yaraArch = Environment.Is64BitProcess ? "64" : "32";

            var clamDir = Path.Combine(baseDir, "clamav", arch);
            var clamscan = Path.Combine(clamDir, "clamscan.exe");
            var freshclam = Path.Combine(clamDir, "freshclam.exe");
            var clamReady = File.Exists(clamscan);

            var yaraDir = Path.Combine(baseDir, "yara");
            var yaraExe = Path.Combine(yaraDir, $"yara{yaraArch}.exe");
            var yaracExe = Path.Combine(yaraDir, $"yarac{yaraArch}.exe");
            var rulesDir = Path.Combine(baseDir, "rules");
            int yarCount = 0;
            try
            {
                if (Directory.Exists(rulesDir))
                    yarCount = Directory.GetFiles(rulesDir, "*.yar", SearchOption.TopDirectoryOnly).Length;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RuntimeDependencies", $"Énumération rules : {rulesDir}", ex);
            }

            var yaraBinOk = File.Exists(yaraExe);
            var yaraRulesOk = yarCount > 0;
            var yaraReady = yaraBinOk && yaraRulesOk;

            string clamDetail = clamReady
                ? (File.Exists(freshclam) ? "clamscan + freshclam détectés." : "clamscan OK ; freshclam.exe absent (MAJ signatures limitées).")
                : "Téléchargez ClamAV win.x64 et copiez les binaires (README § 3.2).";

            string yaraDetail = yaraReady
                ? $"{yarCount} fichier(s) .yar, {Path.GetFileName(yaraExe)} présent."
                : !yaraBinOk
                    ? $"Copiez yara{yaraArch}.exe et yarac{yaraArch}.exe dans yara/."
                    : $"Aucune règle .yar dans rules/ ({rulesDir}).";

            return new Report
            {
                Items = new[]
                {
                    new DependencyStatus
                    {
                        Name = "ClamAV",
                        IsReady = clamReady,
                        ExpectedPath = clamscan,
                        Detail = clamDetail,
                    },
                    new DependencyStatus
                    {
                        Name = "YARA",
                        IsReady = yaraReady,
                        ExpectedPath = yaraExe,
                        Detail = yaraDetail + (File.Exists(yaracExe) ? "" : " yarac absent — compilation au premier scan."),
                    },
                },
            };
        }

        /// <summary>Journalise un avertissement si des dépendances manquent (appel au démarrage UI).</summary>
        public static void LogReportIfIncomplete()
        {
            var report = Evaluate();
            if (report.IsFullyReady)
            {
                AppLogger.Info("RuntimeDependencies", report.BuildSummaryLine());
                return;
            }

            AppLogger.Warn("RuntimeDependencies", report.BuildSummaryLine());
            foreach (var item in report.Items.Where(i => !i.IsReady))
                AppLogger.Warn("RuntimeDependencies", $"{item.Name} : {item.Detail} ({item.ExpectedPath})");
        }
    }
}
