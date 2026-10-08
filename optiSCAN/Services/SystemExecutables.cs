using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Chemins complets des outils Windows lancés par optiSCAN.
    /// </summary>
    /// <remarks>
    /// Un nom nu (<c>"sc.exe"</c>) passe par l'ordre de recherche de <c>CreateProcess</c>, où le
    /// dossier courant précède System32. Lancé depuis le menu contextuel, le dossier courant peut
    /// être celui de l'utilisateur : un <c>sc.exe</c> déposé là serait exécuté à la place de l'outil
    /// système, éventuellement en administrateur. Même règle que <see cref="SystemTweaksService"/>.
    /// </remarks>
    internal static class SystemExecutables
    {
        /// <summary>Outil de System32 (processus x64 : le vrai System32, sans redirection WOW64).</summary>
        public static string System32(string fileName) =>
            Path.Combine(Environment.SystemDirectory, fileName);

        /// <summary>Windows PowerShell 5.1.</summary>
        public static string PowerShell =>
            Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

        /// <summary>Explorateur Windows (dans le dossier Windows, pas dans System32).</summary>
        public static string Explorer =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
    }
}
