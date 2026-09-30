using optiSCAN.Services;

namespace optiSCAN.Tests;

internal sealed class TestNavigationService : INavigationService
{
    public string CurrentView { get; private set; } = string.Empty;

    public event EventHandler<string>? Navigated;

    public void NavigateTo(string name)
    {
        CurrentView = name;
        Navigated?.Invoke(this, name);
    }

    public bool HasPanel(string name) => false;
}
