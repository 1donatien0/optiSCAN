using optiSCAN.Services;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace optiSCAN.Converters
{
    /// <summary>
    /// Visible si le chemin bindé correspond à un fichier encore en quarantaine.
    /// Paramètre <c>NotQuarantined</c> : visible quand le fichier n'est pas en quarantaine.
    /// </summary>
    public sealed class QuarantinePathVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var path = value as string;
            var isQuarantined = !string.IsNullOrWhiteSpace(path)
                && ServiceContainer.Views.Quarantine.GetEntries()
                    .Any(e => string.Equals(e.OriginalPath, path, StringComparison.OrdinalIgnoreCase));

            var showWhenNotQuarantined = string.Equals(
                parameter as string, "NotQuarantined", StringComparison.OrdinalIgnoreCase);
            var visible = showWhenNotQuarantined ? !isQuarantined : isQuarantined;
            return visible ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}