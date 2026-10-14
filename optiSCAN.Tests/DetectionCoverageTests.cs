using System.Runtime.InteropServices;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Couverture de détection (7 octobre 2026) : exécutables reconnus à leur en-tête quelle que
/// soit l'extension, liste d'extensions élargie, rundll32/regsvr32, clés USB, objet job de clamd.
/// </summary>
public sealed class DetectionCoverageTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "optiscan_cov_" + Guid.NewGuid().ToString("N"));

    public DetectionCoverageTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch { /* nettoyage best effort */ }
    }

    /// <summary>En-tête DOS + signature PE à <paramref name="lfanew"/>.</summary>
    private static byte[] MinimalPe(int lfanew = 0x80, int length = 0x200)
    {
        var bytes = new byte[length];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(lfanew).CopyTo(bytes, 0x3C);
        if (lfanew + 4 <= length)
        {
            bytes[lfanew] = (byte)'P';
            bytes[lfanew + 1] = (byte)'E';
        }
        return bytes;
    }

    // ── En-tête PE ───────────────────────────────────────────────────────────────

    [Fact]
    public void Pe_header_is_recognized_whatever_the_extension()
    {
        var path = Path.Combine(_root, "invoice.dat");
        File.WriteAllBytes(path, MinimalPe());

        Assert.True(ExecutableSniffer.IsPortableExecutable(path));
        Assert.True(RiskyFileExtensions.IsRiskyOrExecutable(path));
        Assert.False(RiskyFileExtensions.IsRisky(path));
    }

    [Fact]
    public void A_real_assembly_renamed_to_tmp_is_recognized()
    {
        var copy = Path.Combine(_root, "stage2.tmp");
        File.Copy(typeof(DetectionCoverageTests).Assembly.Location, copy);

        Assert.True(ExecutableSniffer.IsPortableExecutable(copy));
    }

    [Theory]
    [InlineData("MZ this is only text that happens to start with MZ ...")]
    [InlineData("hello world")]
    [InlineData("")]
    public void Text_is_not_an_executable(string content)
    {
        var path = Path.Combine(_root, "notes.dat");
        File.WriteAllText(path, content);

        Assert.False(ExecutableSniffer.IsPortableExecutable(path));
    }

    [Theory]
    [InlineData(0x02)]      // dans la signature MZ
    [InlineData(0x20000)]   // au-delà du plafond
    [InlineData(-4)]
    public void Invalid_pe_offset_is_refused(int lfanew)
    {
        using var stream = new MemoryStream(MinimalPe(lfanew: 0x80));
        var bytes = stream.ToArray();
        BitConverter.GetBytes(lfanew).CopyTo(bytes, 0x3C);

        Assert.False(ExecutableSniffer.IsPortableExecutable(new MemoryStream(bytes)));
    }

    [Fact]
    public void Pe_header_overlapping_the_dos_header_is_recognized()
    {
        // e_lfanew = 4 : « PE\0\0 » aux octets 4 à 7, accepté par le chargeur Windows (audit V10).
        var bytes = new byte[0x200];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(4).CopyTo(bytes, 0x3C);
        bytes[4] = (byte)'P';
        bytes[5] = (byte)'E';

        Assert.True(ExecutableSniffer.IsPortableExecutable(new MemoryStream(bytes)));
    }

    [Theory]
    [InlineData("page.html")]
    [InlineData("facture.svg")]
    [InlineData("lien.url")]
    [InlineData("requete.iqy")]
    [InlineData("formules.slk")]
    [InlineData("classeur.xlsb")]
    [InlineData("pilote.inf")]
    [InlineData("archive.tar")]
    [InlineData("archive.gz")]
    [InlineData("archive.xz")]
    public void Initial_access_formats_are_watched(string name) =>
        Assert.True(RiskyFileExtensions.IsRisky(name));

    [Fact]
    public void Truncated_pe_is_refused() =>
        Assert.False(ExecutableSniffer.IsPortableExecutable(new MemoryStream(MinimalPe(lfanew: 0x80, length: 0x82))));

    [Fact]
    public void Missing_file_is_not_an_executable() =>
        Assert.False(ExecutableSniffer.IsPortableExecutable(Path.Combine(_root, "absent.bin")));

    [Fact]
    public void Header_is_read_while_another_writer_keeps_the_file_open()
    {
        var path = Path.Combine(_root, "growing.bin");
        using var writer = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        writer.Write(MinimalPe());
        writer.Flush();

        Assert.True(ExecutableSniffer.IsPortableExecutable(path));
    }

    // ── Liste d'extensions ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("raccourci.lnk")]
    [InlineData("pack.zip")]
    [InlineData("pack.rar")]
    [InlineData("pack.7z")]
    [InlineData("addin.xll")]
    [InlineData("notes.one")]
    [InlineData("aide.chm")]
    [InlineData("panneau.cpl")]
    [InlineData("script.vbe")]
    [InlineData("app.msix")]
    [InlineData("app.appx")]
    [InlineData("ancien.doc")]
    [InlineData("ancien.xls")]
    [InlineData("lettre.rtf")]
    [InlineData("facture.pdf")]
    [InlineData("pilote.sys")]
    public void Common_delivery_formats_are_listed(string name) =>
        Assert.True(RiskyFileExtensions.IsRisky(name));

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("journal.log")]
    [InlineData("donnees.json")]
    public void Plain_data_is_not_listed(string name) =>
        Assert.False(RiskyFileExtensions.IsRisky(name));

    // ── Lanceurs de DLL ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("rundll32.exe")]
    [InlineData(@"C:\Windows\System32\regsvr32.exe")]
    public void Dll_launchers_are_script_hosts(string process) =>
        Assert.True(RiskyFileExtensions.IsScriptHostProcess(process));

    [Fact]
    public void Rundll32_entry_point_is_split_from_the_file()
    {
        var candidates = ProcessStartMonitor.ExtractCommandLineCandidates(
            @"rundll32.exe C:\Users\a\AppData\Local\Temp\payload.dat,DllRegisterServer");

        Assert.Contains(@"C:\Users\a\AppData\Local\Temp\payload.dat", candidates);
    }

    [Fact]
    public void Quoted_rundll32_target_is_split_too()
    {
        var candidates = ProcessStartMonitor.ExtractCommandLineCandidates(
            "rundll32.exe \"C:\\Users\\a\\My Files\\x.tmp\",Run");

        Assert.Contains(@"C:\Users\a\My Files\x.tmp", candidates);
    }

    // ── Clés USB ─────────────────────────────────────────────────────────────────

    private sealed class NoExclusions : IExclusionSettingsAccessor
    {
        public ExclusionSettings Current { get; } = new();
    }

    [Fact]
    public void Usb_scan_finds_a_renamed_executable()
    {
        var hidden = Path.Combine(_root, "photos", "IMG_0042.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(hidden)!);
        File.WriteAllBytes(hidden, MinimalPe());
        File.WriteAllText(Path.Combine(_root, "photos", "liste.txt"), "rien");

        var files = RemovableDriveDiscovery.CollectRiskyFiles(_root, 10, CancellationToken.None, exclusions: new NoExclusions());

        Assert.Contains(hidden, files);
        Assert.DoesNotContain(files, f => f.EndsWith("liste.txt", StringComparison.Ordinal));
    }

    [Fact]
    public void Usb_scan_puts_executables_first_when_the_budget_is_small()
    {
        for (var i = 0; i < 20; i++)
            File.WriteAllText(Path.Combine(_root, $"doc{i:00}.pdf"), "%PDF-1.7");
        var exe = Path.Combine(_root, "zz_setup.exe");
        File.WriteAllBytes(exe, MinimalPe());

        var files = RemovableDriveDiscovery.CollectRiskyFiles(_root, 3, CancellationToken.None, exclusions: new NoExclusions());

        Assert.Equal(3, files.Count);
        Assert.Equal(exe, files[0]);
    }

    // ── Objet job de clamd ───────────────────────────────────────────────────────

    [Fact]
    public void Job_limit_structure_matches_the_windows_layout()
    {
        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION : 144 octets en 64 bits, 112 en 32 bits.
        var expected = Environment.Is64BitProcess ? 144 : 112;
        Assert.Equal(expected, Marshal.SizeOf<ClamdIsolation.JobObjectExtendedLimitInformation>());
        Assert.Equal(0x2000u, ClamdIsolation.JobObjectLimitKillOnJobClose);
    }
}
