using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiSCAN.Localization;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Views;

/// <summary>Onglet « Tweaks » du panneau Optimiser (performance, confidentialité, interface, maintenance).</summary>
public sealed partial class TweaksPanel : UserControl
{
    public TweaksViewModel ViewModel { get; }

    public TweaksPanel(TweaksViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        ApplyLocalizedLabels();
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(TweaksViewModel.LogText))
                DispatcherQueue.TryEnqueue(() => LogScroll.ChangeView(null, LogScroll.ScrollableHeight, null));
        };
    }

    private void ApplyLocalizedLabels()
    {
        ApplyLabel.Text = LocalizationService.GetString("Twk_Apply");
        StartupLabel.Text = LocalizationService.GetString("Twk_Startup");
        ElevNoteText.Text = LocalizationService.GetString("Twk_ElevNote");
        LogTitle.Text = LocalizationService.GetString("Twk_LogTitle");
        ChkPowerPlan.Content = LocalizationService.GetString("Twk_PowerPlan");
        ChkVisualFx.Content = LocalizationService.GetString("Twk_VisualFx");
        SectionPerfText.Text = LocalizationService.GetString("Twk_SectionPerf");
        ChkTelemetry.Content = LocalizationService.GetString("Twk_Telemetry");
        ChkAds.Content = LocalizationService.GetString("Twk_Ads");
        ChkSuggestions.Content = LocalizationService.GetString("Twk_Suggestions");
        ChkTailored.Content = LocalizationService.GetString("Twk_Tailored");
        SectionPrivacyText.Text = LocalizationService.GetString("Twk_SectionPrivacy");
        ChkShowExt.Content = LocalizationService.GetString("Twk_ShowExt");
        ChkShowHidden.Content = LocalizationService.GetString("Twk_ShowHidden");
        ChkTaskbarLeft.Content = LocalizationService.GetString("Twk_TaskbarLeft");
        ChkHideWidgets.Content = LocalizationService.GetString("Twk_HideWidgets");
        ChkSearchIcon.Content = LocalizationService.GetString("Twk_SearchIcon");
        ChkThisPc.Content = LocalizationService.GetString("Twk_ThisPC");
        SectionUiText.Text = LocalizationService.GetString("Twk_SectionUi");
        ChkDism.Content = LocalizationService.GetString("Twk_Dism");
        ChkDefenderHistory.Content = LocalizationService.GetString("Twk_DefenderHistory");
        SectionMaintText.Text = LocalizationService.GetString("Twk_SectionMaint");
    }

    private async void Apply_Click(object sender, RoutedEventArgs e) => await ViewModel.ApplyAsync();

    private void Startup_Click(object sender, RoutedEventArgs e) => ViewModel.OpenStartupApps();
}
