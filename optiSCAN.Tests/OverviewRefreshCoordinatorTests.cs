// SPDX-License-Identifier: GPL-3.0-or-later
using Moq;
using optiSCAN.Coordinators;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Views;

namespace optiSCAN.Tests;

public sealed class OverviewRefreshCoordinatorTests
{
    [Fact]
    public void RefreshProtectionAndRecommendations_updates_protected_headline_when_engines_ready()
    {
        var panel = new Mock<IOverviewPanel>(MockBehavior.Strict);
        panel.Setup(p => p.UpdateProtectionHeadline(true, null));
        panel.Setup(p => p.UpdateRecommendations(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<bool>(), It.IsAny<string?>()));
        panel.Setup(p => p.UpdateSecurityPosture(It.IsAny<SecurityPostureReport>()));
        panel.Setup(p => p.UpdatePlatformProtectionStatus(It.IsAny<PlatformProtectionStatusReport>()));

        var posture = new Mock<ISecurityPostureService>(MockBehavior.Strict);
        posture.Setup(s => s.Evaluate(It.IsAny<SecurityPostureContext>()))
            .Returns(new SecurityPostureReport { Score = 80 });

        var ctx = new OverviewRefreshContext(
            panel.Object,
            ClamInstalled: true,
            YaraRulesCount: 12,
            YaraAvailable: true,
            CleanHistory: Array.Empty<CleanSession>(),
            ScanHistory: Array.Empty<ScanSession>(),
            LastFreshclamUpdate: DateTime.UtcNow,
            RealTimeProtectionEnabled: true,
            RealTimeProtectionRunning: true,
            SignatureAutoUpdateEnabled: true,
            SecurityPosture: posture.Object);

        OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(ctx);

        panel.Verify(p => p.UpdateProtectionHeadline(true, null), Times.Once);
        posture.Verify(s => s.Evaluate(It.IsAny<SecurityPostureContext>()), Times.Once);
    }

    [Fact]
    public void RefreshProtectionAndRecommendations_uses_precomputed_platform_status()
    {
        var platform = new PlatformProtectionStatusReport { HasWarnings = true };
        var panel = new Mock<IOverviewPanel>(MockBehavior.Strict);
        panel.Setup(p => p.UpdateProtectionHeadline(It.IsAny<bool>(), null));
        panel.Setup(p => p.UpdateRecommendations(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<bool>(), It.IsAny<string?>()));
        panel.Setup(p => p.UpdateSecurityPosture(It.IsAny<SecurityPostureReport>()));
        panel.Setup(p => p.UpdatePlatformProtectionStatus(platform));

        var posture = new Mock<ISecurityPostureService>();
        posture.Setup(s => s.Evaluate(It.IsAny<SecurityPostureContext>()))
            .Returns(new SecurityPostureReport { Score = 50 });

        var ctx = new OverviewRefreshContext(
            panel.Object,
            ClamInstalled: true,
            YaraRulesCount: 1,
            YaraAvailable: true,
            CleanHistory: Array.Empty<CleanSession>(),
            ScanHistory: Array.Empty<ScanSession>(),
            LastFreshclamUpdate: DateTime.UtcNow,
            RealTimeProtectionEnabled: false,
            RealTimeProtectionRunning: false,
            SignatureAutoUpdateEnabled: true,
            SecurityPosture: posture.Object,
            PlatformStatus: platform);

        OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(ctx);

        // Le rapport précalculé (hors thread UI) est transmis tel quel, sans réévaluation.
        panel.Verify(p => p.UpdatePlatformProtectionStatus(platform), Times.Once);
    }
}
