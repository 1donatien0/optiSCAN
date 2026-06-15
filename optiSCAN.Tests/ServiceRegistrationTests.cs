using Microsoft.Extensions.DependencyInjection;
using optiSCAN.Services;
using optiSCAN.Services.DependencyInjection;

namespace optiSCAN.Tests;

public sealed class ServiceRegistrationTests
{
  [Fact]
  public void AddOptiscanCoreServices_resolves_scan_orchestrator()
  {
    var services = new ServiceCollection();
    services.AddOptiscanCoreServices();
    using var provider = services.BuildServiceProvider();

    var orch = provider.GetRequiredService<ScanOrchestrator>();
    var rtp = provider.GetRequiredService<RealTimeProtection>();

    Assert.NotNull(orch);
    Assert.NotNull(rtp);
    Assert.False(rtp.IsEnabled);
  }
}
