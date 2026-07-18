using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class PlatformProtectionStatusServiceTests
{
  [Fact]
  public void Evaluate_returns_platform_components()
  {
    var report = PlatformProtectionStatusService.Evaluate();

    Assert.NotEmpty(report.Components);
    Assert.Contains(report.Components, c => c.LabelKey.StartsWith("Platform_", StringComparison.Ordinal));
  }

  [Fact]
  public void IsAmsiProviderRegistered_false_when_key_missing()
  {
    var path = Path.Combine(Path.GetTempPath(), "missing_amsi.dll");
    Assert.False(PlatformProtectionStatusService.IsAmsiProviderRegistered(path));
  }

  [Fact]
  public void Evaluate_shows_amsi_inactive_when_platform_disabled()
  {
    var prefs = new UserPreferences { UsePlatformProtectionService = false };
    var accessor = new InMemoryPrefsAccessor(prefs);
    var report = PlatformProtectionStatusService.Evaluate(accessor);

    Assert.Contains(report.Components, c =>
        c.LabelKey is "Platform_AmsiPresentInactive" or "Platform_AmsiDllMissing"
        && c.State == PlatformComponentState.NotApplicable);
  }

  private sealed class InMemoryPrefsAccessor(UserPreferences current) : IUserPreferencesAccessor
  {
    public UserPreferences Current { get; } = current;
  }
}
