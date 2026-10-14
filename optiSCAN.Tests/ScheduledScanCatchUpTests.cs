using System.Xml.Linq;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScheduledScanCatchUpTests
{
    [Fact]
    public void Task_definition_catches_up_missed_runs_with_least_privilege()
    {
        var xml = ScheduledScanService.BuildTaskXml(@"C:\Program Files\optiSCAN\optiSCAN.exe", new TimeSpan(2, 30, 0), new DateTime(2026, 10, 13), @"PC\jean");
        var doc = XDocument.Parse(xml);
        string Value(string name) => doc.Descendants().Single(e => e.Name.LocalName == name).Value;

        Assert.Equal("true", Value("StartWhenAvailable"));
        Assert.Equal("LeastPrivilege", Value("RunLevel"));
        Assert.Equal("InteractiveToken", Value("LogonType"));
        Assert.Equal("2026-10-13T02:30:00", Value("StartBoundary"));
        Assert.Equal("1", Value("DaysInterval"));
        Assert.Equal(@"C:\Program Files\optiSCAN\optiSCAN.exe", Value("Command"));
        Assert.Equal("--fullscan --quiet", Value("Arguments"));
        Assert.Equal(@"PC\jean", Value("UserId"));
        Assert.True(ScheduledScanService.TryParseNextRunFromTaskXml(xml, out var next));
        Assert.Equal(2, next.Hour);
        Assert.Equal(30, next.Minute);
    }

    [Fact]
    public void Task_definition_omits_user_when_unknown()
    {
        var xml = ScheduledScanService.BuildTaskXml(@"C:\x\optiSCAN.exe", TimeSpan.FromHours(2), DateTime.Today, null);
        Assert.DoesNotContain("UserId", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void Legacy_task_without_catch_up_is_upgraded_at_same_time()
    {
        const string legacy = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers><CalendarTrigger><StartBoundary>2025-01-01T03:15:00</StartBoundary></CalendarTrigger></Triggers>
              <Settings><StartWhenAvailable>false</StartWhenAvailable></Settings>
            </Task>
            """;
        Assert.True(ScheduledScanService.NeedsCatchUpUpgrade(legacy, out var time));
        Assert.Equal(new TimeSpan(3, 15, 0), time);

        var current = ScheduledScanService.BuildTaskXml(@"C:\x\optiSCAN.exe", TimeSpan.FromHours(2), DateTime.Today, null);
        Assert.False(ScheduledScanService.NeedsCatchUpUpgrade(current, out _));
        Assert.False(ScheduledScanService.NeedsCatchUpUpgrade("pas du xml", out _));
    }
}
