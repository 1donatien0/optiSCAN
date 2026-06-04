using System.IO;

namespace optiSCAN.Services
{
    /// <summary>Extensions de fichiers à risque (exécutables, scripts, macros Office).</summary>
    internal static class RiskyFileExtensions
    {
        public static readonly HashSet<string> All = new(
            new[] { ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".docm", ".xlsm", ".pptm" },
            StringComparer.OrdinalIgnoreCase);

        public static bool IsRisky(string filePath) =>
            All.Contains(Path.GetExtension(filePath));
    }
}
