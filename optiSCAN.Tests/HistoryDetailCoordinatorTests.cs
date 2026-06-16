using optiSCAN.Coordinators;
using optiSCAN.Localization;

namespace optiSCAN.Tests;

[Collection("Localization")]
public sealed class HistoryDetailCoordinatorTests
{
    public HistoryDetailCoordinatorTests() => LocalizationService.ApplyCulture("fr-FR");

    [Fact]
    public void HideDetailPanels_with_empty_view_does_not_throw()
    {
        var coordinator = new HistoryDetailCoordinator();
        coordinator.HideDetailPanels(new HistoryDetailView());
    }

    [Fact]
    public void ShowCleanDetail_with_null_session_and_empty_view_does_not_throw()
    {
        var coordinator = new HistoryDetailCoordinator();
        coordinator.ShowCleanDetail(new HistoryDetailView(), session: null);
    }
}
