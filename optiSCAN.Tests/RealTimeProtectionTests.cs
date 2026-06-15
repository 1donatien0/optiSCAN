using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class RealTimeProtectionTests
{
  [Fact]
  public void Start_then_Stop_toggles_IsEnabled()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var q = new QuarantineManager(Path.Combine(Path.GetTempPath(), "optiscan_rtp_q_" + Guid.NewGuid().ToString("N")));
    var rtp = new RealTimeProtection(orch, q, new NotificationService());

    Assert.False(rtp.IsEnabled);
    rtp.Start();
    Assert.True(rtp.IsEnabled);
    rtp.Start();
    Assert.True(rtp.IsEnabled);
    rtp.Stop();
    Assert.False(rtp.IsEnabled);
    rtp.Dispose();
  }

  [Fact]
  public void Suspend_Resume_controls_IsPaused()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var rtp = new RealTimeProtection(orch, new QuarantineManager(), new NotificationService());

    Assert.False(rtp.IsPaused);
    rtp.Suspend();
    Assert.True(rtp.IsPaused);
    rtp.Suspend();
    Assert.True(rtp.IsPaused);
    rtp.Resume();
    Assert.True(rtp.IsPaused);
    rtp.Resume();
    Assert.False(rtp.IsPaused);
    rtp.Dispose();
  }

  private sealed class FakeClam : IClamAvOrchestratorBackend
  {
    public bool IsClamAvInstalled() => true;
    public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed, FilesScanned = files.Count });
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
