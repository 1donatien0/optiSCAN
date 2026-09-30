using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace optiSCAN.WinUI.Services;

/// <summary>
/// Propriétés attachées <c>svc:ThemeBrush.ForegroundKey</c> / <c>svc:ThemeBrush.BackgroundKey</c> :
/// équivalent d'un <c>{ThemeResource}</c> pour les couleurs choisies à l'exécution (code-behind,
/// <c>x:Bind</c> dans un DataTemplate). Un pinceau posé par code (<c>Foreground = GetBrush(...)</c>)
/// reste figé sur le thème du moment : après une bascule clair ↔ sombre, le texte devenait illisible.
/// Ici la clé est mémorisée et réappliquée à chaque changement de thème de l'élément
/// (<see cref="FrameworkElement.ActualThemeChanged"/>) et de l'accent (<see cref="WinUiThemeManager.ThemeChanged"/>).
/// Le thème est celui de l'élément (<see cref="FrameworkElement.ActualTheme"/>), donc le volet
/// reçoit la même variante que le reste de la fenêtre.
/// </summary>
public static class ThemeBrush
{
    public static readonly DependencyProperty ForegroundKeyProperty = DependencyProperty.RegisterAttached(
        "ForegroundKey", typeof(string), typeof(ThemeBrush), new PropertyMetadata(null, OnKeyChanged));

    public static readonly DependencyProperty BackgroundKeyProperty = DependencyProperty.RegisterAttached(
        "BackgroundKey", typeof(string), typeof(ThemeBrush), new PropertyMetadata(null, OnKeyChanged));

    private static readonly DependencyProperty IsHookedProperty = DependencyProperty.RegisterAttached(
        "IsHooked", typeof(bool), typeof(ThemeBrush), new PropertyMetadata(false));

    // Éléments suivis pour les changements d'accent (qui ne modifient pas ActualTheme).
    private static readonly List<WeakReference<FrameworkElement>> Tracked = new();
    private static readonly object TrackedLock = new();
    private static bool _managerHooked;

    public static string? GetForegroundKey(DependencyObject obj) => obj.GetValue(ForegroundKeyProperty) as string;

    public static void SetForegroundKey(DependencyObject obj, string? value) => obj.SetValue(ForegroundKeyProperty, value);

    public static string? GetBackgroundKey(DependencyObject obj) => obj.GetValue(BackgroundKeyProperty) as string;

    public static void SetBackgroundKey(DependencyObject obj, string? value) => obj.SetValue(BackgroundKeyProperty, value);

    private static void OnKeyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement element)
            return;

        Hook(element);
        Apply(element);
    }

    private static void Hook(FrameworkElement element)
    {
        if ((bool)element.GetValue(IsHookedProperty))
            return;
        element.SetValue(IsHookedProperty, true);

        element.ActualThemeChanged += (s, _) => Apply(s);
        // Avant l'insertion dans l'arbre, ActualTheme vaut le thème de l'application : recalcul au chargement.
        element.Loaded += (s, _) => Apply((FrameworkElement)s);

        lock (TrackedLock)
        {
            Tracked.RemoveAll(w => !w.TryGetTarget(out _));
            Tracked.Add(new WeakReference<FrameworkElement>(element));
            if (!_managerHooked)
            {
                _managerHooked = true;
                WinUiThemeManager.ThemeChanged += (_, _) => ReapplyAll();
            }
        }
    }

    private static void ReapplyAll()
    {
        List<FrameworkElement> alive;
        lock (TrackedLock)
        {
            alive = new List<FrameworkElement>(Tracked.Count);
            foreach (var w in Tracked)
                if (w.TryGetTarget(out var fe))
                    alive.Add(fe);
        }

        foreach (var element in alive)
        {
            var queue = element.DispatcherQueue;
            if (queue == null)
                continue;
            if (queue.HasThreadAccess)
                Apply(element);
            else
                queue.TryEnqueue(() => Apply(element));
        }
    }

    /// <summary>Réapplique les pinceaux de l'élément pour son thème courant.</summary>
    public static void Apply(FrameworkElement element)
    {
        var theme = element.ActualTheme;

        var fgKey = GetForegroundKey(element);
        if (!string.IsNullOrWhiteSpace(fgKey) && WinUiThemeManager.GetBrush(fgKey, theme) is { } fg)
        {
            switch (element)
            {
                case TextBlock tb: tb.Foreground = fg; break;
                case IconElement icon: icon.Foreground = fg; break;
                case Control control: control.Foreground = fg; break;
                case ContentPresenter cp: cp.Foreground = fg; break;
            }
        }

        var bgKey = GetBackgroundKey(element);
        if (!string.IsNullOrWhiteSpace(bgKey) && WinUiThemeManager.GetBrush(bgKey, theme) is { } bg)
        {
            switch (element)
            {
                case Border border: border.Background = bg; break;
                case Panel panel: panel.Background = bg; break;
                case Control control: control.Background = bg; break;
            }
        }
    }
}
