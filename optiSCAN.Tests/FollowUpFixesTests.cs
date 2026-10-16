// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class RestoredContentGraceTests
{
    [Fact]
    public void Restored_file_is_spared_only_for_same_path_same_content_and_limited_time()
    {
        RestoredContentGrace.ResetForTests();
        var now = new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc);
        var path = Path.Combine(Path.GetTempPath(), "restored.exe");
        RestoredContentGrace.Register(path, "ABCDEF", now);

        Assert.True(RestoredContentGrace.IsGranted(path, "abcdef", now.AddMinutes(1)));
        Assert.False(RestoredContentGrace.IsGranted(path, "123456", now.AddMinutes(1)));
        Assert.False(RestoredContentGrace.IsGranted(path + ".other", "ABCDEF", now.AddMinutes(1)));
        Assert.False(RestoredContentGrace.IsGranted(path, "ABCDEF", now + RestoredContentGrace.Duration + TimeSpan.FromSeconds(1)));
        RestoredContentGrace.ResetForTests();
    }
}

public sealed class ProtectionHealthTests
{
    [Fact]
    public void Unhealthy_real_time_protection_degrades_the_badge()
    {
        Assert.Equal(ProtectionBadgeLevel.Active,
            ProtectionStatusEvaluator.Evaluate(true, true, 10, true, true));
        Assert.Equal(ProtectionBadgeLevel.Degraded,
            ProtectionStatusEvaluator.Evaluate(true, true, 10, true, true, realTimeProtectionHealthy: false));
    }
}

public sealed class TweakUndoTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "optiscan_undo_" + Guid.NewGuid().ToString("N") + ".json");

    public TweakUndoTests() => TweakUndoStore.PathOverride = _path;

    public void Dispose()
    {
        TweakUndoStore.PathOverride = null;
        try { File.Delete(_path); } catch { }
    }

    [Fact]
    public void Only_the_first_original_value_is_kept()
    {
        TweakUndoStore.RecordRegistryOriginal(@"Software\X", "A", existed: true, value: 1);
        TweakUndoStore.RecordRegistryOriginal(@"software\x", "a", existed: true, value: 0);
        TweakUndoStore.RecordRegistryOriginal(@"Software\X", "B", existed: false, value: 0);
        TweakUndoStore.RecordPowerPlanOriginal("381b4222-f694-41f0-9685-ff5bb260df2e");
        TweakUndoStore.RecordPowerPlanOriginal("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");

        var snapshot = TweakUndoStore.Load();
        Assert.Equal(2, snapshot.Registry.Count);
        Assert.Equal(1, snapshot.Registry[0].Value);
        Assert.False(snapshot.Registry[1].Existed);
        Assert.Equal("381b4222-f694-41f0-9685-ff5bb260df2e", snapshot.PowerPlanGuid);
        Assert.True(TweakUndoStore.HasPendingUndo);

        TweakUndoStore.Save(new TweakUndoStore.Snapshot());
        Assert.False(TweakUndoStore.HasPendingUndo);
        Assert.False(File.Exists(_path));
    }

    [Theory]
    [InlineData("Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)", "381b4222-f694-41f0-9685-ff5bb260df2e")]
    [InlineData("GUID du mode de gestion de l’alimentation : 8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C  (Performances élevées)", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c")]
    [InlineData("", null)]
    [InlineData("pas de guid", null)]
    public void Active_power_plan_is_read_in_any_language(string output, string? expected)
    {
        Assert.Equal(expected, SystemTweaksService.ParsePowerPlanGuid(output));
    }

    [Fact]
    public void Telemetry_undo_is_a_known_elevated_action()
    {
        Assert.Contains("telemetry-undo", SystemTweaksService.KnownElevatedTweakIds);
        var commands = SystemTweaksService.ElevatedTelemetryUndoCommands().ToList();
        Assert.Contains(commands, c => c.Tool == "reg.exe" && c.Arguments.Contains("delete"));
        Assert.Contains(commands, c => c.Tool == "sc.exe" && c.Arguments.Contains("auto"));
    }
}
