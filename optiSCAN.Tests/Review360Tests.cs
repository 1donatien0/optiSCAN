using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Revue 360 (série V) : chemins réseau dans la surveillance des processus, temps réel jamais
/// suspendu par un scan, hôte sans boîte de dialogue, service arrêté plutôt que vide.
/// </summary>
public sealed class Review360Tests
{
    // ── V1 : aucun chemin réseau ni de périphérique ouvert avec le jeton du service ──────

    [Theory]
    [InlineData(@"\\attaquant\partage\x.exe")]
    [InlineData(@"\\attaquant@80\dav\x.dll")]
    [InlineData(@"\\?\UNC\attaquant\partage\x.exe")]
    [InlineData(@"\\?\C:\Windows\x.exe")]
    [InlineData(@"\\.\pipe\x")]
    [InlineData(@"//attaquant/partage/x.exe")]
    [InlineData(@"C:x.exe")]
    [InlineData(@"x.exe")]
    [InlineData(@"C:\Users\a\x.txt:flux")]
    [InlineData(@"C:\Users\a\\attaquant\x")]
    [InlineData("")]
    public void Network_and_device_paths_are_never_candidates(string path) =>
        Assert.False(ProcessStartMonitor.IsLocalCandidatePath(path));

    [Fact]
    public void Local_drive_path_is_a_candidate() =>
        Assert.True(ProcessStartMonitor.IsLocalCandidatePath(@"C:\Users\a\AppData\Local\Temp\payload.dat"));

    [Fact]
    public void Unc_tokens_are_extracted_but_rejected_before_any_access()
    {
        var candidates = ProcessStartMonitor.ExtractCommandLineCandidates(
            @"cmd.exe /c type ""\\attaquant\partage\x.js"" \\attaquant@80\dav\y.dll");

        Assert.All(candidates, c => Assert.False(ProcessStartMonitor.IsLocalCandidatePath(c)));
    }

    // ── V2 : aucun scan ne coupe le temps réel ──────────────────────────────────────

    [Fact]
    public void Scans_never_suspend_real_time_protection()
    {
        var root = ResolveRepoRoot();
        if (root == null)
            return;

        foreach (var relative in new[]
                 {
                     Path.Combine("optiSCAN", "ViewModels", "ScanViewModel.ScanRun.cs"),
                     Path.Combine("optiSCAN", "Services", "RemovableDriveScanService.cs"),
                     Path.Combine("optiSCAN", "Services", "ScanOrchestrator.cs"),
                 })
        {
            var code = File.ReadAllText(Path.Combine(root, relative));
            Assert.DoesNotContain(".Suspend()", code, StringComparison.Ordinal);
        }
    }

    // ── V3 : abonnement sans interrogation en premier ────────────────────────────────

    [Fact]
    public void Process_monitor_prefers_kernel_start_events()
    {
        Assert.Contains("Win32_ProcessStartTrace", ProcessStartMonitor.TraceQuery, StringComparison.Ordinal);
        Assert.DoesNotContain("WITHIN", ProcessStartMonitor.TraceQuery, StringComparison.Ordinal);
    }

    // ── V5 et V11 : hôte sans interface, service arrêté avec une erreur ─────────────

    [Fact]
    public void Headless_modes_never_show_a_dialog_and_supervisor_pings_the_host()
    {
        var root = ResolveRepoRoot();
        if (root == null)
            return;

        var app = File.ReadAllText(Path.Combine(root, "optiSCAN", "App.xaml.cs"));
        var guard = app.IndexOf("if (_noInteractiveUi)", StringComparison.Ordinal);
        var dialog = app.IndexOf("MessageBox.Show(", StringComparison.Ordinal);
        Assert.True(guard > 0 && dialog > guard, "ShowCrashDialog doit sortir avant MessageBox en mode sans interface");

        var service = File.ReadAllText(Path.Combine(root, "optiSCAN.Service", "ProtectionWindowsService.cs"));
        Assert.Contains("PingHostAsync", service, StringComparison.Ordinal);
        Assert.Contains("StopApplication()", service, StringComparison.Ordinal);
    }

    private static string? ResolveRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++)
        {
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln")))
                return dir;
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }
}
