using System.IO;

namespace optiSCAN.Services
{
    /// <summary>Extensions de fichiers à risque (exécutables, scripts, macros Office, archives suspectes).</summary>
    internal static class RiskyFileExtensions
    {
        public static readonly HashSet<string> All = new(
            new[]
            {
                // Exécutables, pilotes, panneaux de configuration, installeurs
                ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".ocx", ".sys",
                ".msi", ".msp", ".msc", ".jar", ".apk",
                ".msix", ".msixbundle", ".appx", ".appxbundle", ".appinstaller", ".application",
                // Scripts et hôtes de scripts
                ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
                ".wsc", ".hta", ".py", ".pyw", ".reg", ".scf",
                // Raccourcis et fichiers qui lancent une commande
                ".lnk", ".settingcontent-ms", ".library-ms",
                // Documents à macros ou à contenu actif (formats anciens compris)
                ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam", ".xll",
                ".doc", ".xls", ".ppt", ".rtf", ".one", ".chm", ".pdf",
                // Archives et images disque (ClamAV les ouvre)
                ".zip", ".rar", ".7z", ".cab",
                ".iso", ".img", ".vhd", ".vhdx",
            },
            StringComparer.OrdinalIgnoreCase);

        public static readonly HashSet<string> ScriptHosts = new(
            new[]
            {
                "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "msbuild.exe",
                // Chargent une DLL de n'importe quelle extension : rundll32 x.dat,Entry / regsvr32 /s x.tmp
                "rundll32.exe", "regsvr32.exe",
            },
            StringComparer.OrdinalIgnoreCase);

        public static bool IsRisky(string filePath) =>
            All.Contains(Path.GetExtension(filePath));

        /// <summary>
        /// Extension listée, ou contenu PE quelle que soit l'extension (lecture de l'en-tête).
        /// À n'appeler que hors du chemin chaud : chaque appel ouvre le fichier.
        /// </summary>
        public static bool IsRiskyOrExecutable(string filePath) =>
            IsRisky(filePath) || ExecutableSniffer.IsPortableExecutable(filePath);

        public static bool IsExecutable(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".scr", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".com", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".msi", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsScriptHostProcess(string? processName) =>
            !string.IsNullOrWhiteSpace(processName)
            && ScriptHosts.Contains(processName.Split('\\', '/')[^1]);
    }
}
