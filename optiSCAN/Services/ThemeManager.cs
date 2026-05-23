using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using optiSCAN.Services;

namespace optiSCAN
{
    /// <summary>
    /// Gestionnaire de thèmes unifié.
    /// Permute MaterialDesign ET le dictionnaire Donaby personnalisé.
    /// Persistance via UserPreferences (JSON).
    /// </summary>
    public static class ThemeManager
    {
        private static bool _isDarkTheme = false; // Light par défaut

        public static event EventHandler<bool>? ThemeChanged;

        public static bool IsDarkTheme
        {
            get => _isDarkTheme;
            private set
            {
                if (_isDarkTheme != value)
                {
                    _isDarkTheme = value;
                    ApplyTheme(value);
                    ThemeChanged?.Invoke(null, value);
                }
            }
        }

        /// <summary>
        /// Charge et applique le thème sauvegardé dans UserPreferences.
        /// À appeler une seule fois au démarrage.
        /// </summary>
        public static void Initialize()
        {
            var prefs = UserPreferences.Current;
            if (prefs.SyncWindowsTheme)
            {
                bool dark = IsWindowsAppsDarkTheme();
                _isDarkTheme = dark;
                ApplyTheme(dark);
                prefs.DarkTheme = dark;
                prefs.Save();
            }
            else
            {
                _isDarkTheme = prefs.DarkTheme;
                ApplyTheme(prefs.DarkTheme);
            }
        }

        /// <summary>Indique si Windows est en mode applications sombres (registre Personalize).</summary>
        public static bool IsWindowsAppsDarkTheme()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", writable: false);
                var v = key?.GetValue("AppsUseLightTheme");
                if (v is int light)
                    return light == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThemeManager", "IsWindowsAppsDarkTheme", ex);
            }
            return false;
        }

        /// <summary>Bascule sombre ↔ clair et sauvegarde la préférence.</summary>
        public static void Toggle()
        {
            var prefs = UserPreferences.Current;
            prefs.SyncWindowsTheme = false;
            Apply(!IsDarkTheme);
        }

        /// <summary>Applique explicitement un thème et sauvegarde.</summary>
        public static void Apply(bool dark)
        {
            IsDarkTheme = dark;
            var prefs = UserPreferences.Current;
            prefs.DarkTheme = dark;
            prefs.Save();
        }

        /// <summary>Active ou désactive le suivi du thème Windows.</summary>
        public static void SetSyncWithWindows(bool sync)
        {
            var prefs = UserPreferences.Current;
            prefs.SyncWindowsTheme = sync;
            if (sync)
            {
                bool dark = IsWindowsAppsDarkTheme();
                _isDarkTheme = dark;
                ApplyTheme(dark);
                prefs.DarkTheme = dark;
            }
            prefs.Save();
        }

        private static void ApplyTheme(bool isDark)
        {
            try
            {
                // 1. Material Design base (sombre/clair)
                var paletteHelper = new PaletteHelper();
                var theme = paletteHelper.GetTheme();
                theme.SetBaseTheme(isDark ? BaseTheme.Dark : BaseTheme.Light);
                paletteHelper.SetTheme(theme);

                // 2. Permuter le dictionnaire Donaby personnalisé
                SwapDonabyTheme(isDark);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThemeManager", "ApplyTheme", ex);
            }
        }

        /// <summary>
        /// Remplace le ResourceDictionary Donaby.*.xaml chargé dans App.Resources
        /// par la variante clair ou sombre.
        /// </summary>
        private static void SwapDonabyTheme(bool isDark)
        {
            if (System.Windows.Application.Current?.Resources?.MergedDictionaries == null)
                return;

            var merged = System.Windows.Application.Current.Resources.MergedDictionaries;
            var existing = merged.FirstOrDefault(d =>
                d.Source?.OriginalString.Contains("Donaby.") == true);

            if (existing == null) return;

            int idx = merged.IndexOf(existing);
            merged.Remove(existing);

            var uri = isDark
                ? new Uri("/Themes/Donaby.Dark.xaml", UriKind.Relative)
                : new Uri("/Themes/Donaby.Light.xaml", UriKind.Relative);

            merged.Insert(idx, new System.Windows.ResourceDictionary { Source = uri });
        }
    }
}
