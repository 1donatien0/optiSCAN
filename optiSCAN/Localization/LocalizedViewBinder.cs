using System.Windows;
using System.Windows.Controls;

namespace optiSCAN.Localization
{
    /// <summary>Applique les clés de ressources aux contrôles nommés (code-behind dynamique).</summary>
    internal static class LocalizedViewBinder
    {
        public static void SetText(FrameworkElement root, string controlName, string resourceKey)
        {
            if (root.FindName(controlName) is TextBlock tb)
                tb.Text = LocalizationService.GetString(resourceKey);
            else if (root.FindName(controlName) is ContentControl cc)
                cc.Content = LocalizationService.GetString(resourceKey);
            else if (root.FindName(controlName) is System.Windows.Controls.Button btn)
                btn.Content = LocalizationService.GetString(resourceKey);
        }

        public static void SetTexts(FrameworkElement root, params (string Name, string Key)[] items)
        {
            foreach (var (name, key) in items)
                SetText(root, name, key);
        }
    }
}
