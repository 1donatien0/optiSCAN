using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Services;

/// <summary>Applique les phases d'affichage Nettoyer et Antivirus (visibilité + ProgressRing).</summary>
public static class UiPhaseVisibility
{
    public static void ApplyCleanLogPhase(
        CleanUiPhase phase,
        UIElement logScroll,
        UIElement emptyState,
        ProgressRing logProgress)
    {
        var empty = phase == CleanUiPhase.EmptyResult;
        var busy = phase is CleanUiPhase.Analyzing or CleanUiPhase.Cleaning;

        logScroll.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
        emptyState.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        logProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        logProgress.IsActive = busy;
    }

    public static void ApplyCleanActionPhase(CleanUiPhase phase, ProgressRing actionProgress)
    {
        var busy = phase is CleanUiPhase.Analyzing or CleanUiPhase.Cleaning;
        actionProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        actionProgress.IsActive = busy;
    }

    public static void ApplyAntivirusScanPhase(
        bool scanning,
        bool hasThreats,
        UIElement scanHubPanel,
        UIElement scanProgressPanel,
        UIElement threatsList,
        UIElement emptyThreatsState,
        UIElement quarantineAllButton,
        bool showScanLaunchers)
    {
        if (scanning)
        {
            scanHubPanel.Visibility = Visibility.Collapsed;
            scanProgressPanel.Visibility = Visibility.Visible;
            threatsList.Visibility = Visibility.Visible;
            emptyThreatsState.Visibility = Visibility.Collapsed;
            quarantineAllButton.Visibility = Visibility.Collapsed;
            return;
        }

        // Hors de l'onglet Analyse, les vignettes de scan font croire qu'on y est encore.
        scanHubPanel.Visibility = showScanLaunchers ? Visibility.Visible : Visibility.Collapsed;
        scanProgressPanel.Visibility = Visibility.Collapsed;

        if (hasThreats)
        {
            threatsList.Visibility = Visibility.Visible;
            emptyThreatsState.Visibility = Visibility.Collapsed;
            quarantineAllButton.Visibility = Visibility.Visible;
        }
        else
        {
            threatsList.Visibility = Visibility.Collapsed;
            emptyThreatsState.Visibility = Visibility.Visible;
            quarantineAllButton.Visibility = Visibility.Collapsed;
        }
    }
}
