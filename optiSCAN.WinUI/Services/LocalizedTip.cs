using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using optiSCAN.Localization;

namespace optiSCAN.WinUI.Services;

/// <summary>
/// Propriété attachée : <c>svc:LocalizedTip.Key="Av_Restore"</c> pose l'infobulle ET le nom d'accessibilité
/// traduits. Indispensable pour les boutons-icônes des DataTemplate, où le code-behind n'a pas accès aux éléments.
/// </summary>
public static class LocalizedTip
{
    public static readonly DependencyProperty KeyProperty = DependencyProperty.RegisterAttached(
        "Key",
        typeof(string),
        typeof(LocalizedTip),
        new PropertyMetadata(null, OnKeyChanged));

    public static string GetKey(DependencyObject obj) => obj.GetValue(KeyProperty) as string ?? string.Empty;

    public static void SetKey(DependencyObject obj, string value) => obj.SetValue(KeyProperty, value);

    private static void OnKeyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (e.NewValue is not string key || string.IsNullOrWhiteSpace(key))
            return;

        var text = LocalizationService.GetString(key);
        ToolTipService.SetToolTip(d, text);
        AutomationProperties.SetName(d, text);
    }
}
