using Microsoft.Win32;
using optiSCAN.Services;

namespace optiSCAN.Localization
{
    /// <summary>Menu contextuel Explorateur « Scanner avec optiSCAN » / « Scan with optiSCAN ».</summary>
    internal static class ShellContextMenuSupport
    {
        private const string ShellKey = @"Software\Classes\*\shell";
        private const string LegacyFrenchName = "Scanner avec optiSCAN";
        private const string LegacyEnglishName = "Scan with optiSCAN";

        public static void ApplyForCurrentCulture()
        {
            var menuName = LocalizationService.GetString("Shell_ScanWith");
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe))
                exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exe))
                return;

            try
            {
                RemoveMenu(LegacyFrenchName);
                RemoveMenu(LegacyEnglishName);

                using var shell = Registry.CurrentUser.CreateSubKey(ShellKey);
                if (shell == null) return;

                using var menu = shell.CreateSubKey(menuName);
                menu?.SetValue("Icon", $"{exe},0");
                using var command = menu?.CreateSubKey("command");
                command?.SetValue("", $"\"{exe}\" --scan \"%1\"");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ShellContextMenu", "ApplyForCurrentCulture", ex);
            }
        }

        private static void RemoveMenu(string name)
        {
            try
            {
                using var shell = Registry.CurrentUser.OpenSubKey(ShellKey, writable: true);
                shell?.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
            }
            catch
            {
                /* menu absent */
            }
        }
    }
}
