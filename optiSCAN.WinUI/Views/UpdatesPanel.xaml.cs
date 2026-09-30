using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiSCAN.Localization;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Views;

/// <summary>Onglet « Mises à jour » du panneau Optimiser (applications via winget + Windows Update).</summary>
public sealed partial class UpdatesPanel : UserControl
{
    public UpdatesViewModel ViewModel { get; }

    public UpdatesPanel(UpdatesViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        ApplyLocalizedLabels();
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(UpdatesViewModel.LogText))
                DispatcherQueue.TryEnqueue(() => LogScroll.ChangeView(null, LogScroll.ScrollableHeight, null));
        };
    }

    private void ApplyLocalizedLabels()
    {
        HintText.Text = LocalizationService.GetString("Upd_Hint");
        ScanLabel.Text = LocalizationService.GetString("Upd_Scan");
        UpdateSelectedLabel.Text = LocalizationService.GetString("Upd_InstallSelected");
        UpdateAllLabel.Text = LocalizationService.GetString("Upd_InstallAll");
        WindowsUpdateLabel.Text = LocalizationService.GetString("Upd_Windows");
        ListTitle.Text = LocalizationService.GetString("Upd_ListTitle");
        EmptyTitle.Text = LocalizationService.GetString("Upd_EmptyTitle");
        EmptySubtitle.Text = LocalizationService.GetString("Upd_EmptySub");
        LogTitle.Text = LocalizationService.GetString("Upd_LogTitle");
    }

    private async void Scan_Click(object sender, RoutedEventArgs e) => await ViewModel.ScanAsync();

    private async void UpdateSelected_Click(object sender, RoutedEventArgs e) => await ViewModel.UpdateSelectedAsync();

    private async void UpdateAll_Click(object sender, RoutedEventArgs e) => await ViewModel.UpdateAllAsync();

    private void WindowsUpdate_Click(object sender, RoutedEventArgs e) => ViewModel.OpenWindowsUpdate();
}
