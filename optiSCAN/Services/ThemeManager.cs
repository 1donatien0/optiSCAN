using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using optiSCAN.Services;
using System.Windows;
using WpfApp = System.Windows.Application;

namespace optiSCAN
{
    /// <summary>
    /// Gestionnaire de thèmes unifié.
    /// Permute MaterialDesign ET le dictionnaire Donaby personnalisé.
    /// Persistance via UserPreferences (JSON).
    /// Détection automatique du thème Windows via SystemEvents (sans polling).
    /// Détection automatique du mode Contraste Renforcé système.
    /// </summary>
    public static class ThemeManager
    {
        private static bool _isDarkTheme = false;
        private static bool _highContrast;
        private static bool _watchingSystemEvents;
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
        /// À appeler une seule fois au démarrage (thread UI).
        /// </summary>
        public static void Initialize()
        {
            var prefs = UserPreferences.Current;

            // Détection HC système — priorité sur la préférence utilisateur
            bool systemHc = SystemParameters.HighContrast;
            _highContrast = systemHc || prefs.HighContrastEnabled;

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

            // HC système + thème Windows : réaction immédiate via SystemEvents (sans polling).
            StartSystemEventsWatcher();
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
            _highContrast = enabled || SystemParameters.HighContrast;
            ApplyTheme(_isDarkTheme);
        }

        /// <summary>Bascule sombre ↔ clair et sauvegarde la préférence.</summary>
        public static void Toggle()
        {
            var prefs = UserPreferences.Current;
            prefs.SyncWindowsTheme = false;
            prefs.Save();
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
                Apply(dark);
                _lastWindowsDarkTheme = dark;
            }
            else
            {
                Apply(prefs.DarkTheme);
            }
        }

        // ── Abonnement à SystemEvents (zéro polling) ──────────────────────

        private static void StartSystemEventsWatcher()
        {
            if (_watchingSystemEvents)
                return;
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            _watchingSystemEvents = true;
        }

        private static void StopSystemEventsWatcher()
        {
            if (!_watchingSystemEvents)
                return;
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            _watchingSystemEvents = false;
            _lastWindowsDarkTheme = null;
        }

        /// <summary>
        /// Déclenché par Windows lors d'un changement de préférences utilisateur
        /// (thème, couleurs, contraste renforcé). Exécuté sur un thread arbitraire
        /// → dispatch vers le thread UI.
        /// </summary>
        private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category != UserPreferenceCategory.General
                && e.Category != UserPreferenceCategory.Color
                && e.Category != UserPreferenceCategory.Accessibility)
                return;

            var dispatcher = WpfApp.Current?.Dispatcher;
            if (dispatcher == null)
                return;

            _ = dispatcher.InvokeAsync(() =>
            {
                // 1. Contraste Renforcé système (priorité) — même sans SyncWindowsTheme
                bool systemHc = SystemParameters.HighContrast;
                bool newHc = systemHc || UserPreferences.Current.HighContrastEnabled;
                bool hcChanged = _highContrast != newHc;
                if (hcChanged)
                {
                    _highContrast = newHc;
                    ApplyTheme(_isDarkTheme);
                }

                // 2. Thème clair/sombre (seulement si SyncWindowsTheme activé)
                if (!UserPreferences.Current.SyncWindowsTheme)
                    return;

                bool dark = IsWindowsAppsDarkTheme();
                if (_lastWindowsDarkTheme.HasValue && _lastWindowsDarkTheme.Value == dark && !hcChanged)
                    return;

                _lastWindowsDarkTheme = dark;
                IsDarkTheme = dark;
                var prefs = UserPreferences.Current;
                prefs.DarkTheme = dark;
                prefs.Save();
            });
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
        /// par la variante clair, sombre ou contraste renforcé.
        /// </summary>
        private static void SwapDonabyTheme(bool isDark)
        {
            if (WpfApp.Current?.Resources?.MergedDictionaries == null)
                return;

            var merged = WpfApp.Current.Resources.MergedDictionaries;

            Uri uri;
            if (_highContrast)
                uri = new Uri("/Themes/Donaby.HighContrast.xaml", UriKind.Relative);
            else
                uri = isDark
                    ? new Uri("/Themes/Donaby.Dark.xaml", UriKind.Relative)
                    : new Uri("/Themes/Donaby.Light.xaml", UriKind.Relative);

            var existing = merged.FirstOrDefault(d =>
                d.Source?.OriginalString.Contains("Donaby.", StringComparison.OrdinalIgnoreCase) == true);

            if (existing != null)
            {
                int idx = merged.IndexOf(existing);
                merged.Remove(existing);
                merged.Insert(idx, new ResourceDictionary { Source = uri });
                return;
            }

            // PaletteHelper.SetTheme peut retirer Donaby.* des merged dicts — réinsérer avant Controls.xaml.
            int insertIdx = merged.Count;
            for (int i = 0; i < merged.Count; i++)
            {
                var src = merged[i].Source?.OriginalString ?? string.Empty;
                if (src.Contains("Controls.xaml", StringComparison.OrdinalIgnoreCase))
                {
                    insertIdx = i;
                    break;
                }
            }

            merged.Insert(insertIdx, new ResourceDictionary { Source = uri });
        }
    }
}
