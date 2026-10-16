// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using optiSCAN.Models;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>Côté service du fournisseur AMSI : opération <c>scan_buffer</c>.</summary>
public sealed class AmsiScanBufferTests
{
    private const string Marker = "OPTISCAN-AMSI-TEST-MARKER";

    private static async Task<T> WithServer<T>(bool enabled, MarkerYara yara, Func<ProtectionPipeClient, Task<T>> body)
    {
        var pipeName = "optiSCAN_Amsi_" + Guid.NewGuid().ToString("N");
        var orch = new ScanOrchestrator(new CleanClam(), yara);
        var server = new ProtectionPipeServer(orch, pipeName, enableScanBuffer: enabled);
        server.Start();
        try
        {
            await Task.Delay(200);
            using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
            return await body(client);
        }
        finally
        {
            await server.StopAsync();
            server.Dispose();
        }
    }

    [Fact]
    public async Task Scan_buffer_is_refused_unless_the_host_enables_it()
    {
        var response = await WithServer(false, new MarkerYara(), c =>
            c.ScanBufferAsync(Encoding.UTF8.GetBytes("Write-Host ok"), "amsi_content.ps1"));
        Assert.False(response.Ok);
        Assert.Equal("Opération non disponible", response.Message);
    }

    [Fact]
    public async Task Clean_script_is_clean_and_marked_content_is_detected()
    {
        var yara = new MarkerYara();
        var (clean, threat) = await WithServer(true, yara, async c =>
        {
            var a = await c.ScanBufferAsync(Encoding.UTF8.GetBytes("Get-ChildItem"), "amsi_content.ps1");
            var b = await c.ScanBufferAsync(Encoding.UTF8.GetBytes("iex '" + Marker + "'"), "amsi_content.ps1");
            return (a, b);
        });

        Assert.True(clean.Ok, clean.Message);
        Assert.True(clean.Clean);
        Assert.True(threat.Ok, threat.Message);
        Assert.False(threat.Clean);
        Assert.Equal("Test.Amsi.Marker", threat.ThreatName);
        Assert.Equal(".ps1", Path.GetExtension(yara.LastPath));
    }

    [Fact]
    public async Task Same_content_is_answered_from_cache()
    {
        var yara = new MarkerYara();
        await WithServer(true, yara, async c =>
        {
            for (var i = 0; i < 5; i++)
            {
                var r = await c.ScanBufferAsync(Encoding.UTF8.GetBytes("Get-Process"), "amsi_content.ps1");
                Assert.True(r.Ok, r.Message);
            }
            return 0;
        });

        Assert.Equal(1, yara.Calls);
    }

    [Fact]
    public async Task Oversized_or_invalid_buffers_are_refused()
    {
        var (big, bad) = await WithServer(true, new MarkerYara(), async c =>
        {
            var a = await c.ScanBufferAsync(new byte[ProtectionPipeServer.MaxScanBufferBytes + 1], "amsi_content.ps1");
            var b = await c.SendAsync(new ProtectionPipeRequest
            {
                Operation = ProtectionPipeOperations.ScanBuffer,
                BufferBase64 = "@@not-base64@@",
            });
            return (a, b);
        });

        Assert.False(big.Ok);
        Assert.False(bad.Ok);
    }

    [Fact]
    public async Task PowerShell_utf16_content_is_matched_as_text()
    {
        var yara = new MarkerYara();
        var threat = await WithServer(true, yara, c =>
            c.ScanBufferAsync(Encoding.Unicode.GetBytes("iex '" + Marker + "'"), "amsi_content.ps1"));
        Assert.True(threat.Ok, threat.Message);
        Assert.False(threat.Clean);
    }

    [Fact]
    public void Utf16_detection_leaves_binary_content_untouched()
    {
        var utf16 = Encoding.Unicode.GetBytes("Write-Host 'é'");
        Assert.Equal("Write-Host 'é'", Encoding.UTF8.GetString(ProtectionPipeServer.NormalizeAmsiText(utf16)));
        var withBom = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("abc")).ToArray();
        Assert.Equal("abc", Encoding.UTF8.GetString(ProtectionPipeServer.NormalizeAmsiText(withBom)));
        var binary = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00 };
        Assert.Same(binary, ProtectionPipeServer.NormalizeAmsiText(binary));
        var ascii = Encoding.ASCII.GetBytes("Get-Process");
        Assert.Same(ascii, ProtectionPipeServer.NormalizeAmsiText(ascii));
    }

    [Theory]
    [InlineData("amsi_content.ps1", "amsi_content.ps1")]
    [InlineData("x.vbs", "amsi_content.vbs")]
    [InlineData("..\\..\\Windows\\evil.exe", "amsi_content.txt")]
    [InlineData("COM1", "amsi_content.txt")]
    [InlineData(null, "amsi_content.txt")]
    public void Content_name_is_never_taken_from_the_client(string? requested, string expected) =>
        Assert.Equal(expected, ProtectionPipeServer.AmsiContentName(requested));

    [Fact]
    public void Native_provider_and_installer_are_wired()
    {
        var dir = AppContext.BaseDirectory;
        string? root = null;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln"))) { root = dir; break; }
        if (root == null)
            return;

        var provider = File.ReadAllText(Path.Combine(root, "native", "optiSCAN.AmsiProvider", "amsi_provider.cpp"));
        Assert.Contains("A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B", provider, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AMSI_RESULT_NOT_DETECTED", provider, StringComparison.Ordinal);
        var client = File.ReadAllText(Path.Combine(root, "native", "optiSCAN.AmsiProvider", "pipe_client.cpp"));
        Assert.Contains("optiSCAN.Host.exe", client, StringComparison.Ordinal);
        Assert.Contains("QueryServiceStatusEx", client, StringComparison.Ordinal);
        var rc = File.ReadAllText(Path.Combine(root, "native", "optiSCAN.AmsiProvider", "version.rc"));
        var props = File.ReadAllText(Path.Combine(root, "Directory.Build.props"));
        var version = System.Text.RegularExpressions.Regex.Match(props, "<Version>([^<]+)</Version>").Groups[1].Value;
        Assert.Contains("\"ProductVersion\", \"" + version + "\"", rc, StringComparison.Ordinal);
        Assert.Contains("\"ProductName\", \"optiSCAN\"", rc, StringComparison.Ordinal);
        var setup = File.ReadAllText(Path.Combine(root, "installer", "setup.iss"));
        Assert.Contains("optiSCAN.AmsiProvider.dll", setup, StringComparison.Ordinal);
        Assert.Contains("regserver", setup, StringComparison.Ordinal);
    }

    private sealed class MarkerYara : IYaraOrchestratorBackend
    {
        public int Calls;
        public string LastPath = string.Empty;
        public bool IsAvailable => true;
        public int RulesCount => 1;

        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            LastPath = filePath;
            var text = File.ReadAllText(filePath);
            var matches = new List<YaraMatch>();
            if (text.Contains(Marker, StringComparison.Ordinal))
                matches.Add(new YaraMatch { RuleName = "Test.Amsi.Marker", FilePath = filePath });
            return Task.FromResult(matches);
        }

        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());

        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
    }

    private sealed class CleanClam : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed, FilesScanned = 1 });
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed });
    }
}
