using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScanThreatMergerTests
{
    [Fact]
    public void AggregateClamByPath_merges_multiple_virus_names_per_file()
    {
        var path = @"C:\infected\file.exe";
        var threats = new[]
        {
            new ThreatInfo { FilePath = path, VirusName = "Trojan.A", DetectedBy = "ClamAV" },
            new ThreatInfo { FilePath = path, VirusName = "Trojan.B", DetectedBy = "ClamAV" },
        };

        var byPath = ScanThreatMerger.AggregateClamByPath(threats);

        Assert.Single(byPath);
        Assert.Contains("Trojan.A", byPath[path].VirusName);
        Assert.Contains("Trojan.B", byPath[path].VirusName);
    }

    [Fact]
    public void Merge_combines_clam_and_yara_on_same_path()
    {
        var path = @"C:\x\mal.dll";
        var clam = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = path,
            Status = ScanStatus.Completed,
            Threats =
            {
                new ThreatInfo { FilePath = path, VirusName = "Win.Malware", DetectedBy = "ClamAV" }
            }
        };
        var yara = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = path,
            Status = ScanStatus.Completed,
            Threats =
            {
                new ThreatInfo { FilePath = path, VirusName = "Suspicious_DLL", DetectedBy = "YARA" }
            }
        };

        var merged = ScanThreatMerger.Merge(ScanType.File, path, clam, yara);

        Assert.Single(merged.Threats);
        Assert.Equal("ClamAV+YARA", merged.Threats[0].DetectedBy);
        Assert.Contains("Win.Malware", merged.Threats[0].VirusName);
        Assert.Contains("YARA:Suspicious_DLL", merged.Threats[0].VirusName);
    }
}
