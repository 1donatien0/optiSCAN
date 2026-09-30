using optiSCAN.Services;
using optiSCAN.Strings;

namespace optiSCAN.WinUI.Services;

public sealed class WinUiNavigationService : INavigationService
{
    private static readonly Dictionary<string, string> TagByPanelId = new(StringComparer.OrdinalIgnoreCase)
    {
        [OptiscanStrings.PanelIds.Overview] = "overview",
        [OptiscanStrings.PanelIds.Clean] = "clean",
        [OptiscanStrings.PanelIds.Antivirus] = "antivirus",
        [OptiscanStrings.PanelIds.History] = "history",
        [OptiscanStrings.PanelIds.Options] = "options",
    };

    private readonly Action<string> _navigate;

    public WinUiNavigationService(Action<string> navigate) => _navigate = navigate;

    public string CurrentView { get; private set; } = OptiscanStrings.PanelIds.Overview;

    public event EventHandler<string>? Navigated;

    public void NavigateTo(string name)
    {
        var tag = TagByPanelId.TryGetValue(name, out var mapped) ? mapped : name.ToLowerInvariant();
        CurrentView = name;
        _navigate(tag);
        Navigated?.Invoke(this, name);
    }

    /// <summary>Notifie un changement de panneau déclenché par la barre latérale (sans re-navigation).</summary>
    public void NotifyPanelShown(string tag)
    {
        var panelId = TagByPanelId.FirstOrDefault(kv => kv.Value.Equals(tag, StringComparison.OrdinalIgnoreCase)).Key
                      ?? OptiscanStrings.PanelIds.Overview;
        if (string.Equals(CurrentView, panelId, StringComparison.OrdinalIgnoreCase))
            return;
        CurrentView = panelId;
        Navigated?.Invoke(this, panelId);
    }

    public bool HasPanel(string name) => TagByPanelId.ContainsKey(name);
}
