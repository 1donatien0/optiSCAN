using MaterialDesignThemes.Wpf;

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
            bool saved = Services.UserPreferences.Current.DarkTheme;
            _isDarkTheme = saved;
            ApplyTheme(saved);
        }

        /// <summary>Bascule sombre ↔ clair et sauvegarde la préférence.</summary>
        public static void Toggle()
        {
            IsDarkTheme = !IsDarkTheme;
            Services.UserPreferences.Current.DarkTheme = IsDarkTheme;
            Services.UserPreferences.Current.Save();
        }

        /// <summary>Applique explicitement un thème et sauvegarde.</summary>
        public static void Apply(bool dark)
        {
            IsDarkTheme = dark;
            Services.UserPreferences.Current.DarkTheme = dark;
            Services.UserPreferences.Current.Save();
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
                System.Diagnostics.Debug.WriteLine($"[ThemeManager] ApplyTheme: {ex.Message}");
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
