using System.IO;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Textes visibles pendant un scan : une seule « analyse optiSCAN », sans exposer
    /// les moteurs internes (ClamAV, YARA, etc.) — comme les suites grand public multi-moteurs.
    /// </summary>
    internal static class ScanUserDisplay
    {
        public static string ScanStarting(ScanType type, string? path = null) => type switch
        {
            ScanType.QuickScan => "Analyse rapide en cours…",
            ScanType.FullScan => "Analyse complète en cours…",
            ScanType.Folder => $"Analyse du dossier : {path}",
            ScanType.File => $"Analyse du fichier : {Path.GetFileName(path ?? "")}",
            _ => "Analyse en cours…"
        };

        public static string Preparation => "Préparation de l'analyse…";
        public static string Ready => "Prêt — analyse disponible.";
        public static string ReadyDegraded => "Analyse limitée — vérifiez les signatures dans Antivirus.";

        /// <summary>Convertit un message technique de progression en libellé utilisateur.</summary>
        public static string ForProgressMessage(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return "Analyse en cours…";

            var m = StripEnginePrefixes(raw.Trim());

            if (m.StartsWith("Cible ", StringComparison.OrdinalIgnoreCase))
                m = "Zone " + m["Cible ".Length..];

            if (m.StartsWith("scan récursif de", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("démarrage", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("règle ", StringComparison.OrdinalIgnoreCase))
                return "Analyse en cours…";

            if (m.Contains("fichiers analysés", StringComparison.OrdinalIgnoreCase))
                return m;

            return m;
        }

        private static string StripEnginePrefixes(string message)
        {
            var m = message;
            if (m.Length > 0 && m[0] == '[')
            {
                var close = m.IndexOf(']');
                if (close > 0)
                    m = m[(close + 1)..].Trim();
            }

            foreach (var prefix in new[] { "ClamAV — ", "ClamAV : ", "YARA — ", "YARA : " })
            {
                if (m.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    m = m[prefix.Length..].Trim();
                    break;
                }
            }

            return m;
        }
    }
}
