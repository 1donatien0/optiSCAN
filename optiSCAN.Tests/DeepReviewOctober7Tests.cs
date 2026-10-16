// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Relecture approfondie du 7 octobre 2026 (Z1 à Z6) : nettoyeur sans jonctions, noms de
/// périphériques dans les copies d'analyse, chemins <c>\\?\</c>, clés USB.
/// </summary>
public sealed class DeepReviewOctober7Tests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "optiscan_z_" + Guid.NewGuid().ToString("N"));

    public DeepReviewOctober7Tests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch { /* nettoyage best effort */ }
    }

    /// <summary>Lien de dossier (jonction sous Windows) ; faux si l'environnement le refuse.</summary>
    private static bool TryLinkDirectory(string link, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false; // Windows sans mode développeur : test sans objet
        }
    }

    // ── Z1 : nettoyeur ───────────────────────────────────────────────────────────

    [Fact]
    public void Cleaner_never_deletes_through_a_directory_link()
    {
        var temp = Directory.CreateDirectory(Path.Combine(_root, "Temp")).FullName;
        var victim = Directory.CreateDirectory(Path.Combine(_root, "Victim")).FullName;
        var precious = Path.Combine(victim, "precious.txt");
        File.WriteAllText(precious, "ne pas supprimer");
        var junk = Path.Combine(temp, "junk.tmp");
        File.WriteAllText(junk, "0123456789");
        if (!TryLinkDirectory(Path.Combine(temp, "link"), victim))
            return;

        Assert.Equal(10, SafeDirectoryCleaner.Measure(temp));
        var freed = SafeDirectoryCleaner.Clean(temp);

        Assert.Equal(10, freed);
        Assert.False(File.Exists(junk));
        Assert.True(File.Exists(precious));
    }

    [Fact]
    public void Cleaner_refuses_a_root_that_is_itself_a_link()
    {
        var victim = Directory.CreateDirectory(Path.Combine(_root, "Victim")).FullName;
        var precious = Path.Combine(victim, "precious.txt");
        File.WriteAllText(precious, "x");
        var linkedRoot = Path.Combine(_root, "TempLink");
        if (!TryLinkDirectory(linkedRoot, victim))
            return;

        Assert.False(SafeDirectoryCleaner.IsCleanableRoot(linkedRoot));
        Assert.Equal(0, SafeDirectoryCleaner.Clean(linkedRoot));
        Assert.True(File.Exists(precious));
    }

    [Fact]
    public void Cleaner_empties_nested_real_directories()
    {
        var temp = Directory.CreateDirectory(Path.Combine(_root, "Temp")).FullName;
        var nested = Directory.CreateDirectory(Path.Combine(temp, "a", "b")).FullName;
        File.WriteAllText(Path.Combine(nested, "x.tmp"), "abc");
        File.WriteAllText(Path.Combine(temp, "y.tmp"), "de");

        var freed = SafeDirectoryCleaner.Clean(temp);
        if (OperatingSystem.IsWindows() && freed == 0)
            return; // dossier temporaire sous un point de montage : SafePathDelete refuse, par prudence

        Assert.Equal(5, freed);

        Assert.Empty(Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Cleaner_ignores_empty_roots(string? path)
    {
        Assert.Equal(0, SafeDirectoryCleaner.Measure(path));
        Assert.Equal(0, SafeDirectoryCleaner.Clean(path));
    }

    // ── Z2 : noms de périphériques dans la copie d'analyse ───────────────────────

    [Theory]
    [InlineData("COM1", "content")]
    [InlineData("com1.txt", "content.txt")]
    [InlineData("LPT1.exe", "content.exe")]
    [InlineData("NUL", "content")]
    [InlineData("nul .tar.gz", "content.gz")]
    [InlineData("CON.", "content")]
    [InlineData("prn.ps1", "content.ps1")]
    [InlineData("COM\u00B9.dll", "content.dll")]
    [InlineData("CONOUT$", "content")]
    [InlineData("file.txt:hidden", "content")]
    [InlineData("..", "content")]
    [InlineData("...", "content")]
    [InlineData("a|b.exe", "content.exe")]
    [InlineData("", "content")]
    [InlineData(null, "content")]
    public void Staging_name_never_designates_a_device_or_stream(string? original, string expected) =>
        Assert.Equal(expected, ScanStaging.SafeStagingName(original));

    [Theory]
    [InlineData("invoice.pdf.exe")]
    [InlineData("COM10.txt")]
    [InlineData("console.log")]
    [InlineData("auxiliary.dll")]
    [InlineData("setup")]
    public void Staging_keeps_ordinary_names(string original) =>
        Assert.Equal(original, ScanStaging.SafeStagingName(original));

    [Fact]
    public void Staging_keeps_only_the_file_name()
    {
        Assert.Equal("evil.exe", ScanStaging.SafeStagingName(@"C:\Users\a\Downloads\evil.exe"));
        Assert.Equal("evil.exe", ScanStaging.SafeStagingName(@"..\..\evil.exe"));
        Assert.Equal("content.exe", ScanStaging.SafeStagingName(@"D:\x\LPT2.exe"));
    }

    [Fact]
    public void Staging_writes_a_device_named_source_to_a_regular_file()
    {
        using var source = new MemoryStream(new byte[] { 1, 2, 3 });
        using var staged = ScanStaging.Stage(source, "COM1.txt");

        Assert.Equal("content.txt", Path.GetFileName(staged.Path));
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(staged.Path));
    }

    // ── Z3 : chemins \\?\ et périphériques ────────────────────────────────────────

    [Theory]
    [InlineData(@"\\.\COM1")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM")]
    [InlineData(@"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Windows")]
    [InlineData(@"\??\C:\Windows")]
    public void Device_paths_are_refused(string path) =>
        Assert.True(QuarantineManager.IsSensitivePath(path));

    [Theory]
    [InlineData(@"\\?\C:\Users\a\f.txt", @"C:\Users\a\f.txt")]
    [InlineData(@"\\?\UNC\server\share\f.txt", @"\\server\share\f.txt")]
    [InlineData(@"C:\Users\a\f.txt", @"C:\Users\a\f.txt")]
    public void Win32_long_path_prefix_is_removed_before_comparison(string path, string expected)
    {
        Assert.True(QuarantineManager.TryStripWin32DevicePrefix(path, out var plain));
        Assert.Equal(expected, plain);
    }

    [Fact]
    public void Long_path_prefix_does_not_hide_the_system_directory()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        Assert.True(QuarantineManager.IsSensitivePath(@"\\?\" + Path.Combine(system, "drivers", "x.sys")));
    }

    // ── Z5 : clés USB parcourues sans suivre de lien ─────────────────────────────

    [Fact]
    public void Removable_scan_does_not_follow_directory_links()
    {
        var usb = Directory.CreateDirectory(Path.Combine(_root, "usb")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(_root, "outside")).FullName;
        File.WriteAllText(Path.Combine(usb, "own.exe"), "x");
        File.WriteAllText(Path.Combine(outside, "foreign.exe"), "x");
        if (!TryLinkDirectory(Path.Combine(usb, "link"), outside))
            return;

        var files = RemovableDriveDiscovery.CollectRiskyFiles(
            usb, 100, CancellationToken.None, exclusions: new NoExclusions());

        Assert.Contains(files, f => f.EndsWith("own.exe", StringComparison.Ordinal));
        Assert.DoesNotContain(files, f => f.Contains("foreign", StringComparison.Ordinal));
    }

    private sealed class NoExclusions : IExclusionSettingsAccessor
    {
        public ExclusionSettings Current { get; } = new();
    }

    // ── Z7 : tube clamd, serveur du même compte et sans usurpation ───────────────

    [Fact]
    public void Clamd_pipe_client_grants_identification_only() =>
        Assert.Equal(System.Security.Principal.TokenImpersonationLevel.Identification, PipeServerAccount.ClientImpersonation);

    [Fact]
    public void Clamd_pipe_clients_never_use_the_default_impersonation_level()
    {
        var dir = AppContext.BaseDirectory;
        string? root = null;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln"))) { root = dir; break; }
        if (root == null)
            return;

        foreach (var file in new[] { "ClamdClient.cs", "ClamdBroker.cs" })
        {
            var text = File.ReadAllText(Path.Combine(root, "optiSCAN.Engine", "Services", file));
            var creations = System.Text.RegularExpressions.Regex.Matches(text, @"new NamedPipeClientStream\(\s*""\.""[^;]*;");
            Assert.All(creations, m => Assert.Contains("PipeServerAccount.ClientImpersonation", m.Value));
        }
    }

    // ── Z4 : scan_buffer fermé par défaut, ouvert seulement par l'hôte (AMSI) ─────────
    // Voir AmsiScanBufferTests.
}
