using System.Text.RegularExpressions;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// L'INF du minifiltre, l'installeur et <see cref="PlatformRegistration"/> doivent déclarer
/// le même service, la même instance et la même altitude : sinon fltmc load échoue.
/// </summary>
public sealed class MinifilterRegistrationConsistencyTests
{
    private static string RepoFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "optiSCAN.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine([dir!.FullName, .. parts]);
    }

    private static string InfString(string inf, string name)
    {
        var m = Regex.Match(inf, @"^\s*" + Regex.Escape(name) + @"\s*=\s*""([^""]*)""", RegexOptions.Multiline);
        Assert.True(m.Success, $"Clé {name} absente de l'INF");
        return m.Groups[1].Value;
    }

    [Fact]
    public void Inf_matches_PlatformRegistration_constants()
    {
        var inf = File.ReadAllText(RepoFile("native", "optiSCAN.Minifilter", "optiSCAN.Minifilter.inf"));

        Assert.Equal(PlatformRegistration.MinifilterServiceName, InfString(inf, "ServiceName"));
        Assert.Equal(PlatformRegistration.MinifilterInstanceName, InfString(inf, "Instance1.Name"));
        Assert.Equal(PlatformRegistration.MinifilterAltitude, InfString(inf, "Instance1.Altitude"));
        Assert.Contains("[DefaultInstall.NTamd64.Services]", inf, StringComparison.Ordinal);
        Assert.Contains("FSFilter Activity Monitor", inf, StringComparison.Ordinal);
    }

    [Fact]
    public void Installer_registers_same_service_instance_and_altitude()
    {
        var iss = File.ReadAllText(RepoFile("installer", "setup.iss"));

        Assert.Contains("create " + PlatformRegistration.MinifilterServiceName, iss, StringComparison.Ordinal);
        Assert.Contains(
            $"Instances\\{PlatformRegistration.MinifilterInstanceName}', 'Altitude', '{PlatformRegistration.MinifilterAltitude}'",
            iss,
            StringComparison.Ordinal);
        Assert.Contains("delete " + PlatformRegistration.MinifilterServiceName, iss, StringComparison.Ordinal);
    }

    [Fact]
    public void Altitude_is_in_activity_monitor_range()
    {
        var altitude = decimal.Parse(PlatformRegistration.MinifilterAltitude, System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(altitude, 360000m, 389999m);
    }

    [Fact]
    public void ScCreateArguments_declare_filesystem_driver_on_demand_with_fltmgr()
    {
        var args = PlatformRegistration.MinifilterScCreateArguments;
        Assert.Contains("type= filesys", args, StringComparison.Ordinal);
        Assert.Contains("start= demand", args, StringComparison.Ordinal);
        Assert.Contains("depend= FltMgr", args, StringComparison.Ordinal);
        Assert.Contains("FSFilter Activity Monitor", args, StringComparison.Ordinal);
    }
}
