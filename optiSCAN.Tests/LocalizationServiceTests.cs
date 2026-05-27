using optiSCAN.Localization;
using optiSCAN.Services;

namespace optiSCAN.Tests;

[CollectionDefinition(nameof(UserPreferencesStorageTests), DisableParallelization = true)]
public sealed class LocalizationServiceTestsCollection;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class LocalizationServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dat;
    private readonly string _legacy;

    public LocalizationServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "optiscan_loc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dat = Path.Combine(_dir, "preferences.dat");
        _legacy = Path.Combine(_dir, "preferences.json");
        LocalizationService.ApplyCulture("fr-FR");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Fact]
    public void English_culture_returns_english_nav_labels()
    {
        LocalizationService.ApplyCulture("en-US");
        Assert.Equal("Home", LocalizationService.GetString("Nav_Home"));
        Assert.Equal("Antivirus", LocalizationService.GetString("Nav_Antivirus"));
        Assert.True(LocalizationService.IsEnglish);
    }

    [Fact]
    public void French_culture_returns_french_nav_labels()
    {
        LocalizationService.ApplyCulture("fr-FR");
        Assert.Equal("Accueil", LocalizationService.GetString("Nav_Home"));
        Assert.False(LocalizationService.IsEnglish);
    }

    [Fact]
    public void NormalizeCulture_maps_short_names()
    {
        LocalizationService.ApplyCulture("en");
        Assert.True(LocalizationService.IsEnglish);
        LocalizationService.ApplyCulture("fr");
        Assert.False(LocalizationService.IsEnglish);
    }
}
