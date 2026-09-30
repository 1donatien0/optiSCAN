using Microsoft.Win32;
using optiSCAN.Services;

namespace optiSCAN.Localization
{
    /// <summary>
    /// Menu contextuel Explorateur optiSCAN (fichiers et dossiers).
    /// Utilise une clé registre stable (<see cref="StableMenuKey"/>) et un libellé localisé.
    /// </summary>
    internal static class ShellContextMenuSupport
    {
        /// <summary>Clé registre stable — le libellé affiché est la valeur (default) localisée.</summary>
        public const string StableMenuKey = "optiSCAN.Scan";

        private static readonly string[] ShellKeys =
        {
            @"Software\Classes\*\shell",
            @"Software\Classes\Directory\shell",
        };

        /// <summary>Toutes les clés shell historiques optiSCAN (noms localisés).</summary>
        internal static readonly string[] LegacyMenuKeys =
        {
            StableMenuKey,
            "Scanner avec optiSCAN",
            "Scan with optiSCAN",
            "ScanWithOptiSCAN",
            "Shell_ScanWith",
        };

        public static void ApplyForCurrentCulture()
        {
            var displayName = LocalizationService.GetString("Shell_ScanWith");
            if (string.IsNullOrWhiteSpace(displayName) || displayName == "Shell_ScanWith")
            {
                displayName = LocalizationService.IsEnglish
                    ? "Scan with optiSCAN"
                    : "Scanner avec optiSCAN";
            }

            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe))
                exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exe))
                return;

            try
            {
                RemoveAllMenus();
                foreach (var shellKey in ShellKeys)
                    RegisterMenu(shellKey, StableMenuKey, displayName, exe);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ShellContextMenu", "ApplyForCurrentCulture", ex);
            }
        }

        /// <summary>Supprime toutes les entrées shell optiSCAN connues (HKCU).</summary>
        public static void RemoveAllMenus()
        {
            foreach (var shellKey in ShellKeys)
            {
                foreach (var menuKey in LegacyMenuKeys)
                    RemoveMenu(shellKey, menuKey);
            }
        }

        private static void RegisterMenu(string shellKey, string menuKey, string displayName, string exe)
        {
            using var shell = Registry.CurrentUser.CreateSubKey(shellKey);
            if (shell == null)
                return;

            using var menu = shell.CreateSubKey(menuKey);
            if (menu == null)
                return;

            menu.SetValue(string.Empty, displayName);
            menu.SetValue("Icon", $"{exe},0");
            using var command = menu.CreateSubKey("command");
            command?.SetValue(string.Empty, $"\"{exe}\" --scan \"%1\"");
        }

        private static void RemoveMenu(string shellKey, string name)
        {
            try
            {
                using var shell = Registry.CurrentUser.OpenSubKey(shellKey, writable: true);
                shell?.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
            }
            catch
            {
                /* menu absent */
            }
        }
    }
}
