using optiSCAN.Models;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ProtectionPipeServerTests
{
  [Fact]
  public async Task Ping_roundtrip_returns_ok()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var server = new ProtectionPipeServer(orch, pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.SendAsync(new ProtectionPipeRequest
      {
        Operation = ProtectionPipeOperations.Ping,
      });

      Assert.True(response.Ok);
      Assert.True(response.Clean);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
    }
  }

  [Fact]
  public async Task ScanPath_clean_file_returns_clean()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var dir = Path.Combine(Path.GetTempPath(), "optiscan_ipc_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var file = Path.Combine(dir, "clean.txt");
    await File.WriteAllTextAsync(file, "hello");

    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var server = new ProtectionPipeServer(orch, pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.ScanPathAsync(file);

      Assert.True(response.Ok);
      Assert.True(response.Clean);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
      try { Directory.Delete(dir, recursive: true); } catch { }
    }
  }

  private sealed class FakeClam : IClamAvOrchestratorBackend
  {
    public bool IsClamAvInstalled() => true;
    public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed });
  }

  private sealed class FakeYara : IYaraOrchestratorBackend
  {
    public bool IsAvailable => true;
    public int RulesCount => 1;
    public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
      Task.FromResult(new List<YaraMatch>());
    public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new List<YaraMatch>());
    public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new List<YaraMatch>());
  }
}
