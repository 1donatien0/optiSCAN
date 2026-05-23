using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using MediaBrush = System.Windows.Media.Brushes;
using MediaColor = System.Windows.Media.Color;
using MediaColorConverter = System.Windows.Media.ColorConverter;
using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Converters
{
    public sealed class ThreatRiskSeverityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => value is ThreatInfo t ? RiskScoringService.Assess(t).Severity : string.Empty;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    public sealed class ThreatRiskColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not ThreatInfo t) return MediaBrush.Gray;
            var hex = RiskScoringService.Assess(t).Color;
            try
            {
                return new SolidColorBrush((MediaColor)MediaColorConverter.ConvertFromString(hex)!);
            }
            catch
            {
                return MediaBrush.Gray;
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
