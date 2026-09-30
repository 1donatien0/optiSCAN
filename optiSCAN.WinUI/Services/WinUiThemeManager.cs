using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.Win32;
using optiSCAN.Services;
using Windows.UI.ViewManagement;
using WinUiApp = Microsoft.UI.Xaml.Application;

namespace optiSCAN.WinUI.Services;

/// <summary>Thème Donaby WinUI — suivi Windows, dérogation et contraste renforcé.</summary>
/// <remarks>
/// Toutes les surcharges (contraste renforcé, preset, couleur d'accent) sont écrites DANS les
/// dictionnaires de thème « Light » / « Dark » d'App.xaml, jamais à la racine : une clé posée à la
/// racine masquerait silencieusement les valeurs par thème (ex. l'accent perso écrasait le navy du HC).
/// Après chaque surcharge, <see cref="RefreshThemeResources"/> force la réévaluation des ThemeResource.
/// </remarks>
public static class WinUiThemeManager
{
    private const string LightKey = "Light";
    private const string DarkKey = "Dark";
    private const string HighContrastAccentHex = "#000080";

    private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();
    private static Action<bool>? _applyDark;
    private static ResourceDictionary? _hcOverlay;
    private static AccessibilitySettings? _accessibility;
    private static WeakReference<FrameworkElement>? _themeRoot;

    public static event EventHandler<bool>? ThemeChanged;

    /// <summary>Préférence clair/sombre de l'utilisateur (indépendante du contraste renforcé).</summary>
    public static bool IsDarkTheme { get; private set; }

    public static bool HighContrast { get; private set; }

    /// <summary>Thème réellement appliqué : le contraste renforcé force le clair.</summary>
    public static bool IsEffectiveDark => IsDarkTheme && !HighContrast;

    public static bool IsAlternateThemeEnabled => !_prefs.Current.SyncWindowsTheme;

    public static void Initialize(IUserPreferencesAccessor preferences, Action<bool> applyDark)
    {
        _prefs = preferences;
        _applyDark = applyDark;
        var prefs = preferences.Current;
        bool dark = prefs.SyncWindowsTheme ? IsWindowsAppsDarkTheme() : prefs.DarkTheme;
        ApplyHighContrastState(prefs.HighContrastEnabled || IsSystemHighContrast(), notify: false);
        ApplyDark(dark, persist: false);
        // Les couleurs d'accent n'existent plus en XAML : forcer une résolution avec les valeurs injectées.
        RefreshThemeResources();
    }

    public static void Apply(bool dark, FrameworkElement root)
    {
        _themeRoot = new WeakReference<FrameworkElement>(root);
        root.RequestedTheme = dark && !HighContrast ? ElementTheme.Dark : ElementTheme.Light;
    }

    public static bool IsDark(FrameworkElement root) =>
        root.ActualTheme == ElementTheme.Dark;

    /// <summary>
    /// Résout une brosse pour le thème effectivement appliqué. À utiliser dans le code-behind à la place
    /// de <c>Application.Current.Resources[key]</c>, qui suit le thème de Windows et non celui de l'app.
    /// </summary>
    public static Brush? GetBrush(string key) => GetBrush(key, ElementTheme.Default);

    /// <summary>
    /// Résout une brosse pour un thème donné (<see cref="ElementTheme.Default"/> = thème effectif de l'app).
    /// Cherche aussi dans les dictionnaires de thème fusionnés (ressources système WinUI :
    /// <c>TextFillColorSecondaryBrush</c>…), sinon ces clés suivaient le thème de Windows.
    /// Préférer <see cref="ThemeBrush"/> pour tout pinceau posé par code : il suit les bascules de thème.
    /// </summary>
    public static Brush? GetBrush(string key, ElementTheme theme)
    {
        var appResources = WinUiApp.Current?.Resources;
        if (appResources == null)
            return null;

        bool dark = theme switch
        {
            ElementTheme.Dark => true,
            ElementTheme.Light => false,
            _ => IsEffectiveDark,
        };

        if (FindThemed(appResources, dark, key, 0) is Brush themedBrush)
            return themedBrush;

        return appResources.TryGetValue(key, out var v) ? v as Brush : null;
    }

    // WinUI nomme « Default » le dictionnaire sombre de ses ressources système.
    private static readonly string[] DarkThemeKeys = { DarkKey, "Default" };
    private static readonly string[] LightThemeKeys = { LightKey };

    private static object? FindThemed(ResourceDictionary dict, bool dark, string key, int depth)
    {
        if (depth > 4)
            return null;

        foreach (var themeKey in dark ? DarkThemeKeys : LightThemeKeys)
        {
            if (dict.ThemeDictionaries.TryGetValue(themeKey, out var td)
                && td is ResourceDictionary themeDict
                && themeDict.TryGetValue(key, out var value))
                return value;
        }

        for (int i = dict.MergedDictionaries.Count - 1; i >= 0; i--)
        {
            if (FindThemed(dict.MergedDictionaries[i], dark, key, depth + 1) is { } found)
                return found;
        }

        return null;
    }

    public static bool IsWindowsAppsDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", writable: false);
            var v = key?.GetValue("AppsUseLightTheme");
            if (v is int light)
                return light == 0;
            if (v is uint u)
                return u == 0;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("WinUiThemeManager", "IsWindowsAppsDarkTheme", ex);
        }
        return false;
    }

    public static bool IsSystemHighContrast()
    {
        try
        {
            _accessibility ??= new AccessibilitySettings();
            return _accessibility.HighContrast;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("WinUiThemeManager", "IsSystemHighContrast", ex);
            return false;
        }
    }

    public static void SetHighContrast(bool enabled)
    {
        var prefs = _prefs.Current;
        prefs.HighContrastEnabled = enabled;
        prefs.Save();
        ApplyHighContrastState(enabled || IsSystemHighContrast());
    }

    public static void RefreshAccessibilityState()
    {
        ApplyHighContrastState(_prefs.Current.HighContrastEnabled || IsSystemHighContrast());
    }

    public static void SetAlternateThemeEnabled(bool enabled)
    {
        if (enabled)
        {
            var prefs = _prefs.Current;
            prefs.SyncWindowsTheme = false;
            prefs.DarkTheme = !IsWindowsAppsDarkTheme();
            prefs.Save();
            ApplyDark(prefs.DarkTheme);
        }
        else
            SetSyncWithWindows(true);
    }

    public static void SetSyncWithWindows(bool sync)
    {
        var prefs = _prefs.Current;
        prefs.SyncWindowsTheme = sync;
        if (sync)
        {
            bool dark = IsWindowsAppsDarkTheme();
            prefs.DarkTheme = dark;
            prefs.Save();
            ApplyDark(dark);
        }
        else
        {
            prefs.Save();
            ApplyDark(prefs.DarkTheme);
        }
    }

    public static void ApplyExplicit(bool dark)
    {
        var prefs = _prefs.Current;
        prefs.SyncWindowsTheme = false;
        prefs.DarkTheme = dark;
        prefs.Save();
        ApplyDark(dark);
    }

    private static void ApplyHighContrastState(bool enabled, bool notify = true)
    {
        if (enabled == HighContrast && _hcOverlay != null == enabled)
            return;

        HighContrast = enabled;
        MergeHcDictionary(enabled);
        ApplyThemePackOverrides();
        if (!notify)
            return;

        RefreshThemeResources();
        ThemeChanged?.Invoke(null, IsDarkTheme);
    }

    /// <summary>
    /// Fusionne l'overlay HC en DERNIER dans le dictionnaire de thème « Light » : parmi des
    /// MergedDictionaries, le dernier gagne. (À la racine, il pouvait être masqué par ThemeDictionaries.)
    /// </summary>
    private static void MergeHcDictionary(bool enable)
    {
        var lightDict = GetThemeDictionary(LightKey);
        if (lightDict == null)
            return;

        if (_hcOverlay != null)
        {
            lightDict.MergedDictionaries.Remove(_hcOverlay);
            _hcOverlay = null;
        }

        if (enable)
        {
            _hcOverlay = new ResourceDictionary
            {
                Source = new Uri("ms-appx:///Themes/Donaby.HighContrast.xaml"),
            };
            lightDict.MergedDictionaries.Add(_hcOverlay);
        }
    }

    private static void ApplyDark(bool dark, bool persist = true)
    {
        if (persist)
        {
            var prefs = _prefs.Current;
            prefs.DarkTheme = dark;
            prefs.Save();
        }

        IsDarkTheme = dark;
        // Surcharges AVANT l'application du thème : les ThemeResource sont résolues au changement de thème.
        ApplyThemePackOverrides();
        _applyDark?.Invoke(dark);
        ThemeChanged?.Invoke(null, dark);
    }

    /// <summary>Applique le preset et la couleur d'accent utilisateur.</summary>
    public static void ApplyThemePreferences()
    {
        ApplyThemePackOverrides();
        RefreshThemeResources();
        ThemeChanged?.Invoke(null, IsDarkTheme);
    }

    public static void SetThemePreset(string presetId)
    {
        var prefs = _prefs.Current;
        prefs.ThemePresetId = presetId;
        prefs.Save();
        ApplyThemePreferences();
    }

    public static void SetCustomAccentColor(string? hexColor)
    {
        var prefs = _prefs.Current;
        prefs.ThemeAccentColor = string.IsNullOrWhiteSpace(hexColor) ? string.Empty : hexColor.Trim();
        prefs.Save();
        ApplyThemePreferences();
    }

    /// <summary>
    /// Écrit l'accent (preset ou couleur perso) dans chaque dictionnaire de thème.
    /// En contraste renforcé, l'accent navy est imposé : la couleur perso ne doit pas dégrader le contraste.
    /// </summary>
    private static void ApplyThemePackOverrides()
    {
        var prefs = _prefs.Current;
        var pack = WinUiThemePacks.Get(prefs.ThemePresetId);
        var custom = prefs.ThemeAccentColor;

        SetAccent(LightKey, HighContrast ? HighContrastAccentHex
            : string.IsNullOrWhiteSpace(custom) ? pack.LightAccent : custom, dark: false);
        SetAccent(DarkKey, string.IsNullOrWhiteSpace(custom) ? pack.DarkAccent : custom, dark: true);
    }

    // Fonds de référence pour le contraste de l'accent utilisé comme couleur de TEXTE / d'icône
    // (AppBackgroundBrush clair, CardBackgroundBrush sombre = les cas les plus défavorables).
    private static readonly Windows.UI.Color LightReferenceBackground = Windows.UI.Color.FromArgb(255, 0xF5, 0xF5, 0xF5);
    private static readonly Windows.UI.Color DarkReferenceBackground = Windows.UI.Color.FromArgb(255, 0x2C, 0x2C, 0x2C);
    private const double MinTextContrast = 4.5; // WCAG AA, texte courant

    private static void SetAccent(string themeKey, string hex, bool dark)
    {
        var dict = GetThemeDictionary(themeKey);
        if (dict == null || !TryParseColor(hex, out var color))
            return;

        // Une couleur perso (ou un preset) trop claire en thème clair / trop sombre en thème sombre
        // rendait les textes et icônes d'accent illisibles : on l'ajuste jusqu'au contraste AA.
        if (!(HighContrast && !dark))
            color = EnsureContrast(color, dark ? DarkReferenceBackground : LightReferenceBackground, MinTextContrast, lighten: dark);

        // Variantes dérivées de l'accent (utilisées par les contrôles WinUI : AccentFillColor*, etc.).
        dict["SystemAccentColor"] = color;
        dict["SystemAccentColorLight1"] = Mix(color, 255, 0.15);
        dict["SystemAccentColorLight2"] = Mix(color, 255, 0.30);
        dict["SystemAccentColorLight3"] = Mix(color, 255, 0.45);
        dict["SystemAccentColorDark1"] = Mix(color, 0, 0.15);
        dict["SystemAccentColorDark2"] = Mix(color, 0, 0.30);
        dict["SystemAccentColorDark3"] = Mix(color, 0, 0.45);
        dict["AccentBrush"] = new SolidColorBrush(color);
        dict["TextAccent"] = new SolidColorBrush(color);

        // Fond teinté dérivé de l'accent : suit le preset (avant : violet fixe même avec Ocean / Ember).
        // En contraste renforcé, la teinte jaune de Donaby.HighContrast.xaml est conservée.
        // (Une clé posée directement dans le dictionnaire masquerait l'overlay HC fusionné : on la retire.)
        if (!(HighContrast && !dark))
            dict["AccentTintBrush"] = new SolidColorBrush(dark ? Mix(color, 0, 0.72) : Mix(color, 255, 0.88));
        else
            dict.Remove("AccentTintBrush");
    }

    private static double RelativeLuminance(Windows.UI.Color c)
    {
        static double Channel(byte v)
        {
            double s = v / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * Channel(c.R) + 0.7152 * Channel(c.G) + 0.0722 * Channel(c.B);
    }

    private static double ContrastRatio(Windows.UI.Color a, Windows.UI.Color b)
    {
        double la = RelativeLuminance(a), lb = RelativeLuminance(b);
        return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
    }

    /// <summary>Éclaircit (sombre) ou assombrit (clair) la couleur par paliers jusqu'au contraste demandé.</summary>
    internal static Windows.UI.Color EnsureContrast(Windows.UI.Color color, Windows.UI.Color background, double minRatio, bool lighten)
    {
        var current = color;
        for (int i = 0; i < 24 && ContrastRatio(current, background) < minRatio; i++)
            current = Mix(current, lighten ? (byte)255 : (byte)0, 0.08);
        return current;
    }

    /// <summary>Mélange <paramref name="c"/> vers le blanc (255) ou le noir (0).</summary>
    private static Windows.UI.Color Mix(Windows.UI.Color c, byte target, double amount)
    {
        static byte Lerp(byte from, byte to, double t) => (byte)Math.Round(from + (to - from) * t);
        return Windows.UI.Color.FromArgb(255, Lerp(c.R, target, amount), Lerp(c.G, target, amount), Lerp(c.B, target, amount));
    }

    private static ResourceDictionary? GetThemeDictionary(string themeKey)
    {
        var appResources = WinUiApp.Current?.Resources;
        return appResources != null
               && appResources.ThemeDictionaries.TryGetValue(themeKey, out var d)
            ? d as ResourceDictionary
            : null;
    }

    /// <summary>Force la réévaluation des {ThemeResource} (aller-retour de thème sur la racine).</summary>
    private static void RefreshThemeResources()
    {
        if (_themeRoot == null || !_themeRoot.TryGetTarget(out var root))
        {
            _applyDark?.Invoke(IsDarkTheme);
            return;
        }
        root.RequestedTheme = IsEffectiveDark ? ElementTheme.Light : ElementTheme.Dark;
        Apply(IsDarkTheme, root);
    }

    private static bool TryParseColor(string hex, out Windows.UI.Color color)
    {
        color = default;
        if (string.IsNullOrWhiteSpace(hex))
            return false;
        hex = hex.Trim();
        if (hex.StartsWith('#'))
            hex = hex[1..];
        if (hex.Length != 6)
            return false;
        try
        {
            color = Windows.UI.Color.FromArgb(
                255,
                Convert.ToByte(hex[..2], 16),
                Convert.ToByte(hex.Substring(2, 2), 16),
                Convert.ToByte(hex.Substring(4, 2), 16));
            return true;
        }
        catch
        {
            return false;
        }
    }
}
