using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScanUserDisplayTests
{
    [Theory]
    [InlineData("[ClamAV] ClamAV : 120 fichiers analysés…", "120 fichiers analysés…")]
    [InlineData("[YARA] YARA — scan récursif de Temp", "Analyse en cours…")]
    [InlineData("Cible 2/5 : C:\\Users", "Zone 2/5 : C:\\Users")]
    public void ForProgressMessage_hides_engine_branding(string raw, string expected)
    {
        Assert.Equal(expected, ScanUserDisplay.ForProgressMessage(raw));
    }

    [Fact]
    public void ScanStarting_never_mentions_engine_names()
    {
        var msg = ScanUserDisplay.ScanStarting(ScanType.QuickScan);
        Assert.DoesNotContain("ClamAV", msg, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("YARA", msg, StringComparison.OrdinalIgnoreCase);
    }
}
