// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Services;

/// <summary>Migration des préférences thème (logique UI-agnostique).</summary>
public static class ThemePreferenceMigration
{
    /// <summary>
    /// Ancien défaut <c>SyncWindowsTheme=false</c> : si le thème stocké = Windows, activer le suivi.
    /// </summary>
    public static bool TryMigrateToWindowsThemeSync(UserPreferences prefs, bool windowsDark)
    {
        if (prefs.SyncWindowsTheme || prefs.DarkTheme != windowsDark)
            return false;
        prefs.SyncWindowsTheme = true;
        return true;
    }
}
