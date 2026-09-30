namespace optiSCAN.WinUI.Services;

/// <summary>Presets de thème avancés (accent + libellé).</summary>
public static class WinUiThemePacks
{
    public sealed record ThemePack(string Id, string NameKey, string LightAccent, string DarkAccent);

    public static IReadOnlyList<ThemePack> All { get; } =
    [
        // Variante sombre : ≥ 4,5:1 sur CardBackgroundBrush sombre (#2C2C2C) — accent lisible comme texte.
        new("donaby", "ThemePack_Donaby", "#534AB7", "#9F97F0"),
        new("midnight", "ThemePack_Midnight", "#1E3A5F", "#6AAAE8"),
        new("ocean", "ThemePack_Ocean", "#0D7377", "#2BB8BD"),
        new("ember", "ThemePack_Ember", "#B45309", "#F59E0B"),
    ];

    public static ThemePack Get(string? id)
    {
        var key = string.IsNullOrWhiteSpace(id) ? "donaby" : id.Trim();
        return All.FirstOrDefault(p => p.Id.Equals(key, StringComparison.OrdinalIgnoreCase)) ?? All[0];
    }
}
