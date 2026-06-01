using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using optiSCAN.Services;
using System.Windows.Threading;

namespace optiSCAN
{
    /// <summary>
    /// Gestionnaire de thèmes unifié.
    /// Permute MaterialDesign ET le dictionnaire Donaby personnalisé.
    /// Persistance via UserPreferences (JSON).
    /// </summary>
    public static class ThemeManager
    {
        private static bool _isDarkTheme = false; // Clair par défaut
        private static bool _highContrast;
        private static DispatcherTimer? _windowsThemeWatchTimer;
        private static bool? _lastWindowsDarkTheme;

        public static event EventHandler<bool>? ThemeChanged;

        public static bool HighContrast => _highContrast;

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
            _highContrast = prefs.HighContrastEnabled;
            if (prefs.SyncWindowsTheme)
            {
                bool dark = IsWindowsAppsDarkTheme();
                _isDarkTheme = dark;
                ApplyTheme(dark);
                prefs.DarkTheme = dark;
                prefs.Save();
                StartWindowsThemeWatcher();
            }
            else
            {
                _isDarkTheme = prefs.DarkTheme;
                ApplyTheme(prefs.DarkTheme);
                StopWindowsThemeWatcher();
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

        /// <summary>Active ou désactive le thème à contraste renforcé.</summary>
        public static void SetHighContrast(bool enabled)
        {
            var prefs = UserPreferences.Current;
            prefs.HighContrastEnabled = enabled;
            prefs.Save();
            _highContrast = enabled;
            ApplyTheme(_isDarkTheme);
        }

        /// <summary>Bascule sombre ↔ clair et sauvegarde la préférence.</summary>
        public static void Toggle()
        {
            var prefs = UserPreferences.Current;
            prefs.SyncWindowsTheme = false;
            StopWindowsThemeWatcher();
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
                _lastWindowsDarkTheme = dark;
                StartWindowsThemeWatcher();
            }
            else
            {
                StopWindowsThemeWatcher();
            }
            prefs.Save();
        }

        private static void StartWindowsThemeWatcher()
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher == null)
                return;

            if (!dispatcher.CheckAccess())
            {
                _ = dispatcher.InvokeAsync(StartWindowsThemeWatcher);
                return;
            }

            _windowsThemeWatchTimer ??= new DispatcherTimer(
                TimeSpan.FromSeconds(2),
                DispatcherPriority.Background,
                (_, _) => SyncWithWindowsIfChanged(),
                dispatcher);

            if (!_windowsThemeWatchTimer.IsEnabled)
                _windowsThemeWatchTimer.Start();
        }

        private static void StopWindowsThemeWatcher()
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher == null)
                return;

            if (!dispatcher.CheckAccess())
            {
                _ = dispatcher.InvokeAsync(StopWindowsThemeWatcher);
                return;
            }

            _windowsThemeWatchTimer?.Stop();
            _lastWindowsDarkTheme = null;
        }

        private static void SyncWithWindowsIfChanged()
        {
            var prefs = UserPreferences.Current;
            if (!prefs.SyncWindowsTheme)
                return;

            bool dark = IsWindowsAppsDarkTheme();
            if (_lastWindowsDarkTheme.HasValue && _lastWindowsDarkTheme.Value == dark)
                return;

            _lastWindowsDarkTheme = dark;
            IsDarkTheme = dark;
            prefs.DarkTheme = dark;
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

            Uri uri;
            if (_highContrast)
                uri = new Uri("/Themes/Donaby.HighContrast.xaml", UriKind.Relative);
            else
                uri = isDark
                    ? new Uri("/Themes/Donaby.Dark.xaml", UriKind.Relative)
                    : new Uri("/Themes/Donaby.Light.xaml", UriKind.Relative);

            merged.Insert(idx, new System.Windows.ResourceDictionary { Source = uri });
        }
    }
}
