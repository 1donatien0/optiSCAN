namespace optiSCAN.Tests;

/// <summary>
/// Audit A4 : le service doit être relancé par le gestionnaire de services après un plantage ou
/// un arrêt en erreur (<c>StopWithError</c>), sinon la machine reste sans protection.
/// </summary>
public sealed class InstallerServiceRecoveryTests
{
    [Fact]
    public void Installer_configures_service_recovery_actions()
    {
        var setup = File.ReadAllText(Path.Combine(RepoRoot(), "installer", "setup.iss"));

        Assert.Contains("'failure {#ProtectionServiceName} reset= 86400 actions= restart/", setup, StringComparison.Ordinal);
        Assert.Contains("'failureflag {#ProtectionServiceName} 1'", setup, StringComparison.Ordinal);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "optiSCAN.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
