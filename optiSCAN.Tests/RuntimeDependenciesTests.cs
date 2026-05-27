using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class RuntimeDependenciesTests
{
    [Fact]
    public void Evaluate_returns_clamav_and_yara_items()
    {
        var report = RuntimeDependencies.Evaluate();

        Assert.Equal(2, report.Items.Count);
        Assert.Contains(report.Items, i => i.Name == "ClamAV");
        Assert.Contains(report.Items, i => i.Name == "YARA");
        Assert.False(string.IsNullOrWhiteSpace(report.BuildSummaryLine()));
    }

    [Fact]
    public void BuildDetailedMessage_includes_execution_directory_hint()
    {
        var report = RuntimeDependencies.Evaluate();
        var text = report.BuildDetailedMessage();

        Assert.Contains("Répertoire d'exécution", text);
        foreach (var item in report.Items)
            Assert.False(string.IsNullOrWhiteSpace(item.ExpectedPath));
    }
}
