using optiSCAN.Localization;
using optiSCAN.Platform;
using optiSCAN.Services;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using DataGrid = System.Windows.Controls.DataGrid;
using WpfApp = System.Windows.Application;
using WpfButton = System.Windows.Controls.Button;
using WpfMessageBox = System.Windows.MessageBox;

namespace optiSCAN.Views
{
    /// <summary>
    /// Administration de la quarantaine du service SYSTEM. Ouverte par un processus élevé :
    /// le service refuse la liste et les actions à tout autre client. Construite en code
    /// (pas de XAML) : elle sert aussi d'unique fenêtre à l'instance <c>--service-quarantine</c>.
    /// </summary>
    public sealed class ServiceQuarantineWindow : Window
    {
        private readonly ObservableCollection<ServiceQuarantineItem> _items = new();
        private readonly DataGrid _grid;
        private readonly TextBlock _status;
        private readonly TextBlock _intro;
        private readonly WpfButton[] _actions;

        public ServiceQuarantineWindow()
        {
            Title = LocalizationService.GetString("SvcQ_Title");
            Width = 920;
            Height = 560;
            MinWidth = 640;
            MinHeight = 360;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            SetResourceReference(BackgroundProperty, "AppBg");
            SetResourceReference(ForegroundProperty, "TextDark");

            _intro = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10),
                Text = LocalizationService.Format("SvcQ_Intro", ServiceQuarantineStore.RetentionDays),
            };

            _grid = new DataGrid
            {
                ItemsSource = _items,
                AutoGenerateColumns = false,
                CanUserAddRows = false,
                IsReadOnly = true,
                SelectionMode = DataGridSelectionMode.Extended,
                HeadersVisibility = DataGridHeadersVisibility.Column,
            };
            _grid.Columns.Add(new DataGridTextColumn
            {
                Header = LocalizationService.GetString("SvcQ_ColDate"),
                Binding = new System.Windows.Data.Binding(nameof(ServiceQuarantineItem.QuarantinedAt)) { StringFormat = "g" },
                Width = 130,
            });
            _grid.Columns.Add(new DataGridTextColumn
            {
                Header = LocalizationService.GetString("SvcQ_ColFile"),
                Binding = new System.Windows.Data.Binding(nameof(ServiceQuarantineItem.OriginalPath)),
                Width = new DataGridLength(1, DataGridLengthUnitType.Star),
            });
            _grid.Columns.Add(new DataGridTextColumn
            {
                Header = LocalizationService.GetString("SvcQ_ColThreat"),
                Binding = new System.Windows.Data.Binding(nameof(ServiceQuarantineItem.VirusName)),
                Width = 200,
            });
            _grid.Columns.Add(new DataGridTextColumn
            {
                Header = LocalizationService.GetString("SvcQ_ColSize"),
                Binding = new System.Windows.Data.Binding(nameof(ServiceQuarantineItem.OriginalSize)) { Converter = new SizeConverter() },
                Width = 90,
            });
            _grid.SelectionChanged += (_, _) => UpdateButtons();

            _status = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0), TextWrapping = TextWrapping.Wrap };

            var restore = MakeButton("SvcQ_Restore", "PrimaryButton", async () => await RestoreAsync(chooseFolder: false));
            var restoreTo = MakeButton("SvcQ_RestoreTo", "PrimaryButton", async () => await RestoreAsync(chooseFolder: true));
            var delete = MakeButton("SvcQ_Delete", "DangerButton", DeleteAsync);
            var purge = MakeButton("SvcQ_Purge", "DangerButton", PurgeAsync);
            var refresh = MakeButton("SvcQ_Refresh", null, LoadAsync);
            var close = MakeButton("SvcQ_Close", null, () => { Close(); return Task.CompletedTask; });
            _actions = new[] { restore, restoreTo, delete, purge, refresh };

            var buttons = new WrapPanel { HorizontalAlignment = System.Windows.HorizontalAlignment.Right };
            foreach (var b in new[] { restore, restoreTo, delete, purge, refresh, close })
                buttons.Children.Add(b);

            var footer = new DockPanel { Margin = new Thickness(0, 10, 0, 0), LastChildFill = true };
            DockPanel.SetDock(buttons, Dock.Right);
            footer.Children.Add(buttons);
            footer.Children.Add(_status);

            var root = new DockPanel { Margin = new Thickness(16) };
            DockPanel.SetDock(_intro, Dock.Top);
            DockPanel.SetDock(footer, Dock.Bottom);
            root.Children.Add(_intro);
            root.Children.Add(footer);
            root.Children.Add(_grid);
            Content = root;

            Loaded += async (_, _) => await LoadAsync();
        }

        private WpfButton MakeButton(string key, string? styleKey, Func<Task> action)
        {
            var button = new WpfButton
            {
                Content = LocalizationService.GetString(key),
                Margin = new Thickness(6, 0, 0, 0),
                Padding = new Thickness(12, 6, 12, 6),
                MinWidth = 90,
            };
            if (styleKey != null && TryFindResource(styleKey) is Style style)
                button.Style = style;
            button.Click += async (_, _) =>
            {
                SetBusy(true);
                try { await action(); }
                finally { SetBusy(false); }
            };
            return button;
        }

        private void SetBusy(bool busy)
        {
            foreach (var b in _actions)
                b.IsEnabled = !busy;
            if (!busy)
                UpdateButtons();
        }

        private void UpdateButtons()
        {
            var hasSelection = _grid.SelectedItems.Count > 0;
            _actions[0].IsEnabled = hasSelection;
            _actions[1].IsEnabled = _grid.SelectedItems.Count == 1;
            _actions[2].IsEnabled = hasSelection;
            _actions[3].IsEnabled = _items.Count > 0;
        }

        private List<ServiceQuarantineItem> Selected() => _grid.SelectedItems.Cast<ServiceQuarantineItem>().ToList();

        private static ProtectionPipeClient NewClient() => new(timeout: TimeSpan.FromSeconds(60));

        private async Task LoadAsync()
        {
            try
            {
                using var client = NewClient();
                var response = await client.ListServiceQuarantineAsync();
                _items.Clear();
                if (!response.Ok)
                {
                    _status.Text = LocalizationService.Format("SvcQ_Error", response.Message ?? string.Empty);
                    return;
                }

                foreach (var item in response.Entries ?? new List<ServiceQuarantineItem>())
                    _items.Add(item);
                var total = response.Count ?? _items.Count;
                _status.Text = total > _items.Count
                    ? LocalizationService.Format("SvcQ_StatusTruncated", _items.Count, total)
                    : LocalizationService.Format("SvcQ_Status", total, ServiceQuarantineFormatting.FormatBytes(response.TotalBytes ?? 0));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ServiceQuarantineWindow", "Liste", ex);
                _status.Text = LocalizationService.GetString("SvcQ_Unreachable");
            }
            finally
            {
                UpdateButtons();
            }
        }

        private async Task RestoreAsync(bool chooseFolder)
        {
            var selected = Selected();
            if (selected.Count == 0)
                return;

            string? folder = null;
            if (chooseFolder)
            {
                using var dialog = new System.Windows.Forms.FolderBrowserDialog
                {
                    Description = LocalizationService.GetString("SvcQ_RestoreTo"),
                    UseDescriptionForTitle = true,
                };
                if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                    return;
                folder = dialog.SelectedPath;
            }

            foreach (var item in selected)
            {
                if (!Confirm(LocalizationService.Format("SvcQ_ConfirmRestore", item.FileName, item.VirusName), MessageBoxImage.Warning))
                    continue;
                try
                {
                    using var client = NewClient();
                    var response = await client.RestoreServiceQuarantineAsync(item.Id, folder);
                    _status.Text = response.Ok
                        ? LocalizationService.Format("SvcQ_Restored", response.Message ?? item.OriginalPath)
                        : LocalizationService.Format("SvcQ_Error", response.Message ?? string.Empty);
                    if (!response.Ok)
                        break;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ServiceQuarantineWindow", "Restauration", ex);
                    _status.Text = LocalizationService.GetString("SvcQ_Unreachable");
                    break;
                }
            }

            var message = _status.Text;
            await LoadAsync();
            _status.Text = message;
        }

        private async Task DeleteAsync()
        {
            var selected = Selected();
            if (selected.Count == 0)
                return;
            var label = selected.Count == 1 ? selected[0].FileName : selected.Count.ToString("N0", LocalizationService.CurrentCulture);
            if (!Confirm(LocalizationService.Format("SvcQ_ConfirmDelete", label), MessageBoxImage.Warning))
                return;

            try
            {
                using var client = NewClient();
                foreach (var item in selected)
                {
                    var response = await client.DeleteServiceQuarantineAsync(item.Id);
                    if (!response.Ok)
                    {
                        _status.Text = LocalizationService.Format("SvcQ_Error", response.Message ?? string.Empty);
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ServiceQuarantineWindow", "Suppression", ex);
                _status.Text = LocalizationService.GetString("SvcQ_Unreachable");
            }

            await LoadAsync();
        }

        private async Task PurgeAsync()
        {
            if (_items.Count == 0)
                return;
            if (!Confirm(LocalizationService.Format("SvcQ_ConfirmPurge", _items.Count), MessageBoxImage.Warning))
                return;

            try
            {
                using var client = NewClient();
                var response = await client.PurgeServiceQuarantineAsync();
                if (!response.Ok)
                    _status.Text = LocalizationService.Format("SvcQ_Error", response.Message ?? string.Empty);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ServiceQuarantineWindow", "Purge", ex);
                _status.Text = LocalizationService.GetString("SvcQ_Unreachable");
            }

            await LoadAsync();
        }

        private bool Confirm(string message, MessageBoxImage image) =>
            WpfMessageBox.Show(this, message, Title, MessageBoxButton.YesNo, image, MessageBoxResult.No) == MessageBoxResult.Yes;

        private sealed class SizeConverter : IValueConverter
        {
            public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
                value is long size ? ServiceQuarantineFormatting.FormatBytes(size) : string.Empty;

            public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
                throw new NotSupportedException();
        }
    }
}

namespace optiSCAN.Services
{
    internal static class ServiceQuarantineFormatting
    {
        public static string FormatBytes(long bytes) => bytes switch
        {
            < 0 => "?",
            < 1024 => $"{bytes} o",
            < 1024 * 1024 => $"{bytes / 1024.0:F1} Ko",
            < 1024L * 1024 * 1024 => $"{bytes / 1048576.0:F1} Mo",
            _ => $"{bytes / 1073741824.0:F2} Go",
        };
    }
}
