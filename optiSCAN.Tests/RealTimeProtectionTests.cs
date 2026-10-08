using optiSCAN.Models;
using optiSCAN.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;

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
  public void Dispose_can_be_called_twice()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var rtp = new RealTimeProtection(orch, new QuarantineManager(), new NotificationService());
    rtp.Start();
    rtp.Dispose();
    rtp.Dispose();
    Assert.False(rtp.IsEnabled);
  }

  [Fact]
  public void Resume_below_zero_clamps_suspend_count()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var rtp = new RealTimeProtection(orch, new QuarantineManager(), new NotificationService());

    rtp.Resume();
    rtp.Resume();
    Assert.False(rtp.IsPaused);
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

  [Fact]
  public async Task Watcher_queue_stays_bounded_and_reschedules_recovery_under_load()
  {
    if (!OperatingSystem.IsWindows())
      return;

    var id = Guid.NewGuid().ToString("N");
    var watchRoot = Path.Combine(Path.GetTempPath(), "optiscan_rtp_load_" + id);
    var quarantineRoot = Path.Combine(Path.GetTempPath(), "optiscan_rtp_load_q_" + id);
    Directory.CreateDirectory(watchRoot);

    var backend = new RecordingClam();
    var orchestrator = new ScanOrchestrator(backend, new FakeYara());
    var rtp = new RealTimeProtection(
      orchestrator,
      new QuarantineManager(quarantineRoot),
      new NotificationService(),
      watcherRecoveryCooldownMilliseconds: 10);

    try
    {
      rtp.Start(new[] { watchRoot });
      Assert.True(rtp.IsEnabled);

      WriteExecutableBatch(watchRoot, "early", 300);
      await WaitUntilAsync(() => rtp.WatcherRecoveryPassCount > 0, TimeSpan.FromSeconds(10));

      // Cette vague arrive pendant le premier balayage, lorsque de nouveaux événements
      // peuvent dépasser la capacité; ils doivent déclencher un passage supplémentaire.
      WriteExecutableBatch(watchRoot, "late", 180);
      await WaitUntilAsync(() => rtp.WatcherRecoveryRescheduleCount > 0, TimeSpan.FromSeconds(10));
      await WaitUntilAsync(() => rtp.WatcherRecoveryPassCount >= 2, TimeSpan.FromSeconds(20));
      await WaitUntilAsync(() => backend.ScannedNames.Count == 480, TimeSpan.FromSeconds(40));

      Assert.True(rtp.WatcherQueueOverflowCount > 0);
      Assert.True(rtp.MaxPendingWatcherEventsObserved > 0);
      Assert.InRange(rtp.MaxPendingWatcherEventsObserved, 1, RealTimeProtection.MaxPendingWatcherEvents);
      Assert.True(rtp.WatcherRecoveryPassCount >= 2);
      Assert.Equal(0, rtp.PendingWatcherEvents);
    }
    finally
    {
      rtp.Dispose();
      try { Directory.Delete(watchRoot, recursive: true); } catch { /* best effort */ }
      try { Directory.Delete(quarantineRoot, recursive: true); } catch { /* best effort */ }
    }
  }

  [Fact]
  public async Task ScanFileAsync_raises_ThreatDetected_when_orchestrator_finds_threat()
  {
    var dir = Path.Combine(Path.GetTempPath(), "optiscan_rtp_threat_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var sample = Path.Combine(dir, "payload.exe");
    await File.WriteAllBytesAsync(sample, [0x4D, 0x5A]);

    var orch = new ScanOrchestrator(new ThreatClamBackend(), new FakeYara());
    var qDir = Path.Combine(dir, "q");
    var rtp = new RealTimeProtection(orch, new QuarantineManager(qDir), new NotificationService());
    ThreatInfo? detected = null;
    rtp.ThreatDetected += (_, t) => detected = t;

    try
    {
      await InvokeScanFileAsync(rtp, sample, WatcherChangeTypes.Created);
      Assert.NotNull(detected);
      Assert.Equal(sample, detected!.FilePath);
      Assert.Equal("Test.Threat", detected.VirusName);
    }
    finally
    {
      rtp.Dispose();
      try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
    }
  }

  private static async Task InvokeScanFileAsync(
      RealTimeProtection rtp,
      string filePath,
      WatcherChangeTypes changeType)
  {
    var method = typeof(RealTimeProtection).GetMethod(
        "ScanFileAsync",
        System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
    Assert.NotNull(method);
    await (Task)method!.Invoke(rtp, [Path.GetDirectoryName(filePath), filePath, changeType])!;
  }

  private static void WriteExecutableBatch(string root, string prefix, int count)
  {
    for (var i = 0; i < count; i++)
    {
      var path = Path.Combine(root, $"{prefix}-{i:D4}.exe");
      File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00]);
    }
  }

  private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
  {
    var timer = Stopwatch.StartNew();
    while (timer.Elapsed < timeout)
    {
      if (condition())
        return;
      await Task.Delay(25);
    }
    Assert.True(condition(), $"Condition not reached within {timeout}.");
  }

  private sealed class ThreatClamBackend : IClamAvOrchestratorBackend
  {
    public bool IsClamAvInstalled() => true;
    public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult
      {
        Type = ScanType.File,
        TargetPath = filePath,
        Status = ScanStatus.Completed,
        Threats = [new ThreatInfo { FilePath = filePath, VirusName = "Test.Threat", FileSize = 2 }],
      });
    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed, FilesScanned = files.Count });
  }

  private sealed class RecordingClam : IClamAvOrchestratorBackend
  {
    public ConcurrentDictionary<string, byte> ScannedNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool IsClamAvInstalled() => true;

    public async Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
      ScannedNames.TryAdd(Path.GetFileName(filePath), 0);
      await Task.Delay(5, ct);
      return new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed, FilesScanned = 1 };
    }

    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });

    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed, FilesScanned = files.Count });
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
