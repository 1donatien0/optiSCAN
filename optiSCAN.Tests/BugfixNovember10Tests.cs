// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;
using optiSCAN.Services;
using System.Xml.Linq;

namespace optiSCAN.Tests;

/// <summary>Non-régression des corrections du 10 novembre 2026.</summary>
public sealed class BugfixNovember10Tests
{
    // ── Scan planifié : rattrapage possible sur batterie ─────────────────────

    [Fact]
    public void Scheduled_task_may_start_on_battery()
    {
        var xml = ScheduledScanService.BuildTaskXml(@"C:\x\optiSCAN.exe", TimeSpan.FromHours(2), DateTime.Today, null);
        var doc = XDocument.Parse(xml);
        Assert.Equal("false", doc.Descendants().Single(e => e.Name.LocalName == "DisallowStartIfOnBatteries").Value);
        Assert.False(ScheduledScanService.NeedsCatchUpUpgrade(xml, out _));
    }

    [Fact]
    public void Xml_task_blocked_on_battery_is_upgraded_at_same_time()
    {
        const string previous = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers><CalendarTrigger><StartBoundary>2026-10-13T04:45:00</StartBoundary></CalendarTrigger></Triggers>
              <Settings><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StartWhenAvailable>true</StartWhenAvailable></Settings>
            </Task>
            """;
        Assert.True(ScheduledScanService.NeedsCatchUpUpgrade(previous.Trim(), out var time));
        Assert.Equal(new TimeSpan(4, 45, 0), time);
    }

    [Fact]
    public void Xml_task_without_battery_setting_uses_scheduler_default_and_is_upgraded()
    {
        const string noBatteryElement = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers><CalendarTrigger><StartBoundary>2026-10-13T02:00:00</StartBoundary></CalendarTrigger></Triggers>
              <Settings><StartWhenAvailable>true</StartWhenAvailable></Settings>
            </Task>
            """;
        Assert.True(ScheduledScanService.NeedsCatchUpUpgrade(noBatteryElement.Trim(), out _));
    }

    // ── Temps réel : remappage des chemins de la copie analysée ───────────────

    [Theory]
    [InlineData(@"C:\staging\abc\f.zip", true)]
    [InlineData(@"C:\staging\abc\f.zip!inner.exe", true)]
    [InlineData(@"C:\staging\abc\f.zip\inner.exe", true)]
    [InlineData(@"C:\staging\abc\f.zip:stream", true)]
    [InlineData(@"C:\staging\abc\f.zip.bak", false)]
    [InlineData(@"C:\staging\abc\f.zipx", false)]
    [InlineData(@"C:\other\f.zip", false)]
    public void Staged_path_match_respects_member_boundary(string threatPath, bool expected)
    {
        Assert.Equal(expected, RealTimeProtection.IsStagedPathOrMember(threatPath, @"C:\staging\abc\f.zip"));
    }

    [Fact]
    public void Unrelated_threat_sharing_the_staged_prefix_is_not_rebound()
    {
        var result = new ScanResult { TargetPath = @"C:\staging\abc\f.zip" };
        result.Threats.Add(new ThreatInfo { FilePath = @"C:\staging\abc\f.zip.bak", VirusName = "A" });

        RealTimeProtection.RebindStagedResult(result, @"C:\staging\abc\f.zip", @"C:\Users\a\Downloads\f.zip");

        Assert.Equal(@"C:\staging\abc\f.zip.bak", result.Threats[0].FilePath);
    }

    // ── Commande asynchrone : pas de double exécution ─────────────────────────

    [Fact]
    public async Task AsyncRelayCommand_ignores_execute_while_running()
    {
        var runs = 0;
        var gate = new TaskCompletionSource();
        var command = new AsyncRelayCommand(async _ =>
        {
            Interlocked.Increment(ref runs);
            await gate.Task;
        });

        command.Execute(null);
        command.Execute(null);
        gate.SetResult();
        await Task.Yield();

        Assert.Equal(1, runs);
    }
}
