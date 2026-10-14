using Moq;
using optiSCAN.Coordinators;
using optiSCAN.Models;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ServiceDetectionLogTests
{
    private static ThreatInfo Threat(string path, ThreatStatus status = ThreatStatus.Detected)
    {
        var t = ThreatInfo.FromClamAv(path, "Win.Test.EICAR", 68);
        t.Status = status;
        return t;
    }

    [Fact]
    public void Since_returns_only_newer_detections_in_order()
    {
        var log = new ServiceDetectionLog(storePath: null);
        var first = log.Record(Threat(@"C:\Users\a\Downloads\one.exe"));
        var second = log.Record(Threat(@"C:\Users\a\Downloads\two.exe", ThreatStatus.Quarantined));

        Assert.True(second > first);
        Assert.Equal(second, log.LatestSequence);

        var newer = log.Since(first, clientSid: null, elevatedAdministrator: true);
        var item = Assert.Single(newer);
        Assert.Equal(second, item.Sequence);
        Assert.Equal("two.exe", item.FileName);
        Assert.True(item.Quarantined);
        Assert.Equal(2, log.Since(0, null, true).Count);
    }

    [Fact]
    public void Full_path_is_hidden_from_non_admin_outside_their_profile()
    {
        var log = new ServiceDetectionLog(storePath: null);
        log.Record(Threat(@"C:\Users\other\secret\bad.exe"));

        var item = Assert.Single(log.Since(0, clientSid: "S-1-5-21-0-0-0-99999", elevatedAdministrator: false));
        Assert.Null(item.FullPath);
        Assert.Equal("bad.exe", item.FileName);

        var admin = Assert.Single(log.Since(0, null, elevatedAdministrator: true));
        Assert.Equal(@"C:\Users\other\secret\bad.exe", admin.FullPath);
    }

    [Fact]
    public void Capacity_bounds_the_log()
    {
        var log = new ServiceDetectionLog(storePath: null);
        for (var i = 0; i < ServiceDetectionLog.Capacity + 20; i++)
            log.Record(Threat($@"C:\t\f{i}.exe"));
        Assert.Equal(ServiceDetectionLog.Capacity, log.Since(0, null, true).Count);
    }

    [Theory]
    [InlineData(@"C:\Users\jean\Downloads\x.exe", @"C:\Users\jean", true)]
    [InlineData(@"C:\Users\jeanne\x.exe", @"C:\Users\jean", false)]
    [InlineData(@"C:\Users\jean", @"C:\Users\jean", false)]
    [InlineData(null, @"C:\Users\jean", false)]
    public void IsUnder_requires_a_real_child_path(string? path, string folder, bool expected)
    {
        Assert.Equal(expected, ServiceDetectionLog.IsUnder(path, folder));
    }

    [Fact]
    public void Watcher_maps_service_items_to_user_threats()
    {
        var at = new DateTime(2026, 10, 13, 10, 0, 0, DateTimeKind.Utc);
        var threat = ServiceDetectionWatcher.ToThreat(new ServiceDetectionItem
        {
            Sequence = 5,
            DetectedAtUtc = at,
            VirusName = "Win.Test.EICAR",
            Engine = "",
            FileName = "bad.exe",
            FullPath = null,
            Quarantined = true,
        });

        Assert.Equal("bad.exe", threat.FilePath);
        Assert.Equal("ClamAV", threat.DetectedBy);
        Assert.Equal(ThreatStatus.Quarantined, threat.Status);
        Assert.Equal(at.ToLocalTime(), threat.DetectedAt);
    }
}

[Collection("OptiscanPrefs")]
public sealed class GameModeThreatDeferralTests
{
    [Fact]
    public void Threat_alerts_are_kept_during_game_mode_instead_of_dropped()
    {
        var prevGame = UserPreferences.Current.GameModeAutoEnabled;
        try
        {
            var svc = new NotificationService { IsEnabled = true };
            UserPreferences.Current.GameModeAutoEnabled = true;
            DistractionFreeMonitor.ResetForTests(active: true);

            svc.ShowThreatDetected(ThreatInfo.FromClamAv(@"C:\t\a.exe", "Win.Test.A", 10));
            svc.ShowThreatDetected(ThreatInfo.FromClamAv(@"C:\t\b.exe", "Win.Test.B", 10));
            Assert.Equal(2, svc.DeferredCount);

            // Toujours en mode jeu : rien n'est relâché.
            svc.FlushDeferred();
            Assert.Equal(2, svc.DeferredCount);
        }
        finally
        {
            UserPreferences.Current.GameModeAutoEnabled = prevGame;
            UserPreferences.Current.Save();
            DistractionFreeMonitor.ResetForTests();
        }
    }
}

public sealed class ToastIgnoreConfirmationTests
{
    private static ToastActivationCoordinator.Host NewHost(Func<string, string?, bool>? confirm, Action onShow)
    {
        // Strict : toucher aux services (donc à IgnoreThreat) ferait échouer le test.
        var services = new Mock<IViewServices>(MockBehavior.Strict);
        return new ToastActivationCoordinator.Host
        {
            Services = services.Object,
            Navigation = Mock.Of<INavigationService>(),
            ShowWindow = onShow,
            SetStatus = (_, _, _) => { },
            RefreshQuarantineList = () => { },
            RefreshAntivirusView = () => { },
            SelectAntivirusScanTab = () => { },
            SelectAntivirusQuarantineTab = () => { },
            SelectAntivirusSignaturesTab = () => { },
            TriggerManualSignatureUpdate = () => { },
            ConfirmIgnore = confirm,
        };
    }

    [Fact]
    public void Ignore_without_confirmation_never_excludes()
    {
        var shown = 0;
        ToastActivationCoordinator.Handle(
            new ToastActivationEventArgs("ignore", @"C:\t\bad.exe", "Win.Test"),
            NewHost(confirm: null, onShow: () => shown++));
        Assert.Equal(1, shown);
    }

    [Fact]
    public void Ignore_declined_never_excludes_and_passes_threat_details()
    {
        string? askedPath = null;
        string? askedVirus = null;
        ToastActivationCoordinator.Handle(
            new ToastActivationEventArgs("ignore", @"C:\t\bad.exe", "Win.Test"),
            NewHost((p, v) => { askedPath = p; askedVirus = v; return false; }, () => { }));
        Assert.Equal(@"C:\t\bad.exe", askedPath);
        Assert.Equal("Win.Test", askedVirus);
    }
}
