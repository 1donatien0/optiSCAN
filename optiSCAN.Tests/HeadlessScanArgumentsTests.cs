using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class HeadlessScanArgumentsTests
{
    [Theory]
    [InlineData(new[] { "--fullscan" }, HeadlessScanArguments.Mode.FullScan)]
    [InlineData(new[] { "--FULLSCAN", "--quiet" }, HeadlessScanArguments.Mode.FullScan)]
    [InlineData(new[] { "--quickscan" }, HeadlessScanArguments.Mode.QuickScan)]
    [InlineData(new[] { "--service-host" }, HeadlessScanArguments.Mode.ServiceHost)]
    [InlineData(new[] { "--clamd-broker" }, HeadlessScanArguments.Mode.ClamdBroker)]
    [InlineData(new[] { "--clamd-relay" }, HeadlessScanArguments.Mode.ClamdRelay)]
    [InlineData(new[] { "--clamd-stub" }, HeadlessScanArguments.Mode.ClamdStub)]
    [InlineData(new[] { "--clear-defender-history" }, HeadlessScanArguments.Mode.ClearDefenderHistory)]
    [InlineData(new[] { "--guard" }, HeadlessScanArguments.Mode.Guard)]
    [InlineData(new[] { "--service-quarantine" }, HeadlessScanArguments.Mode.ServiceQuarantine)]
    [InlineData(new string[0], HeadlessScanArguments.Mode.None)]
    public void ParseMode_returns_expected(string[] args, HeadlessScanArguments.Mode expected) =>
        Assert.Equal(expected, HeadlessScanArguments.ParseMode(args));

    [Fact]
    public void IsQuiet_detects_flag() =>
        Assert.True(HeadlessScanArguments.IsQuiet(new[] { "--fullscan", "--quiet" }));
}
