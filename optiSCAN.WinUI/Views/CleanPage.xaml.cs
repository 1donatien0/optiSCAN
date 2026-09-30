using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiSCAN.Localization;
using optiSCAN.WinUI.Services;
using optiSCAN.WinUI.ViewModels;
using Windows.ApplicationModel.DataTransfer;

namespace optiSCAN.WinUI.Views;

public sealed partial class CleanPage : UserControl
{
    public CleanViewModel ViewModel { get; }

    public CleanPage(CleanViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        UpdatesTab.Content = new UpdatesPanel(ViewModel.Updates);
        TweaksTab.Content = new TweaksPanel(ViewModel.Tweaks);
        ApplyLocalizedLabels();
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        SyncUi();
    }

    private void ApplyLocalizedLabels()
    {
        CleanTab.Header = LocalizationService.GetString("Opti_TabClean");
        UpdatesTab.Header = LocalizationService.GetString("Opti_TabUpdates");
        TweaksTab.Header = LocalizationService.GetString("Opti_TabTweaks");
        HeroTitleText.Text = LocalizationService.GetString("Clean_Title");
        SubtitleText.Text = LocalizationService.GetString("Clean_Sub");
        TempLabel.Text = LocalizationService.GetString("Clean_TempWin");
        BrowserLabel.Text = LocalizationService.GetString("Clean_Browsers");
        TotalLabel.Text = LocalizationService.GetString("Clean_Total");
        TempSubText.Text = LocalizationService.GetString("Clean_TempSub");
        BrowserSubText.Text = LocalizationService.GetString("Clean_BrowserSub");
        TotalSubText.Text = LocalizationService.GetString("Clean_TotalSub");
        AnalyzeButtonLabel.Text = LocalizationService.GetString("Clean_Analyze");
        CleanButtonLabel.Text = LocalizationService.GetString("Clean_Run");
        ItemsTitle.Text = LocalizationService.GetString("Clean_ItemsTitle");
        SystemTab.Header = LocalizationService.GetString("Clean_System");
        BrowsersTab.Header = LocalizationService.GetString("Clean_BrowsersSection");
        LogTitle.Text = LocalizationService.GetString("Clean_LogTitle");
        EmptyTitle.Text = LocalizationService.GetString("Clean_EmptyTitle");
        EmptySubtitle.Text = LocalizationService.GetString("Clean_EmptySub");
        CopyLogLabel.Text = LocalizationService.GetString("Clean_CopyLog");
    }

    private void SyncUi()
    {
        TempSizeText.Text = ViewModel.TempSizeDisplay;
        BrowserSizeText.Text = ViewModel.BrowserSizeDisplay;
        TotalSizeText.Text = ViewModel.TotalSizeDisplay;
        LogText.Text = ViewModel.LogText;
        AnalyzeButton.IsEnabled = ViewModel.IsAnalyzeEnabled;
        CleanButton.IsEnabled = ViewModel.IsCleanEnabled;
        SyncPhaseUi();
    }

    private void SyncPhaseUi()
    {
        UiPhaseVisibility.ApplyCleanLogPhase(ViewModel.Phase, LogScroll, EmptyState, LogProgress);
        UiPhaseVisibility.ApplyCleanActionPhase(ViewModel.Phase, ActionProgress);
    }

    private void Analyze_Click(object sender, RoutedEventArgs e) =>
        ViewModel.AnalyzeCommand.Execute(null);

    private void Clean_Click(object sender, RoutedEventArgs e) =>
        ViewModel.CleanCommand.Execute(null);

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ViewModel.LogText))
            return;

        var package = new DataPackage();
        package.SetText(ViewModel.LogText);
        Clipboard.SetContent(package);
    }
}
