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

      Assert.True(response.Ok, response.Message);
      Assert.True(response.Clean);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
      try { Directory.Delete(dir, recursive: true); } catch { }
    }
  }

  [Fact]
  public async Task Shutdown_without_token_is_rejected()
  {
    const string token = "test-shutdown-token";
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var server = new ProtectionPipeServer(orch, pipeName, token);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.SendAsync(new ProtectionPipeRequest
      {
        Operation = ProtectionPipeOperations.Shutdown,
      });

      Assert.False(response.Ok);
      Assert.Contains("autoris", response.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
    }
  }

  [Fact]
  public async Task Shutdown_with_valid_token_returns_ok()
  {
    const string token = "test-shutdown-token-ok";
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var shutdownCalled = false;
    var server = new ProtectionPipeServer(orch, pipeName, token, () => shutdownCalled = true);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.SendAsync(new ProtectionPipeRequest
      {
        Operation = ProtectionPipeOperations.Shutdown,
        AuthToken = token,
      });

      Assert.True(response.Ok);
      Assert.True(shutdownCalled);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
    }
  }

  [Fact]
  public async Task ScanPath_sensitive_system_file_is_rejected()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);
    if (string.IsNullOrWhiteSpace(systemRoot))
      return;

    var target = Path.Combine(systemRoot, "kernel32.dll");
    if (!File.Exists(target))
      return;

    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var server = new ProtectionPipeServer(orch, pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.ScanPathAsync(target);
      Assert.False(response.Ok);
      Assert.Contains("refus", response.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
    }
  }

  [Fact]
  public async Task ScanPath_rate_limited_returns_error()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var dir = Path.Combine(Path.GetTempPath(), "optiscan_ipc_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var file = Path.Combine(dir, "clean.txt");
    await File.WriteAllTextAsync(file, "hello");

    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var limiter = new IpcScanRateLimiter(maxPerMinute: 1, maxConcurrent: 1);
    var server = new ProtectionPipeServer(orch, pipeName, scanRateLimiter: limiter);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var first = await client.ScanPathAsync(file);
      Assert.True(first.Ok, first.Message);

      var second = await client.ScanPathAsync(file);
      Assert.False(second.Ok);
      Assert.Contains("débit", second.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
      try { Directory.Delete(dir, recursive: true); } catch { /* test cleanup */ }
    }
  }

  [Fact]
  public async Task Response_carries_current_protocol_version()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var server = new ProtectionPipeServer(new ScanOrchestrator(new FakeClam(), new FakeYara()), pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.Ping });

      Assert.True(response.Ok);
      Assert.Equal(ProtectionIdentifiers.ProtocolVersion, response.ProtocolVersion);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
    }
  }

  [Fact]
  public async Task Newer_client_protocol_is_rejected_explicitly()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var server = new ProtectionPipeServer(new ScanOrchestrator(new FakeClam(), new FakeYara()), pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.SendAsync(new ProtectionPipeRequest
      {
        Operation = ProtectionPipeOperations.Ping,
        ProtocolVersion = ProtectionIdentifiers.ProtocolVersion + 1,
      });

      Assert.False(response.Ok);
      Assert.Contains("Protocole", response.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
    }
  }

  [Fact]
  public async Task SetPolicy_requires_an_elevated_administrator()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var policyFile = Path.Combine(Path.GetTempPath(), "optiscan_policy_" + Guid.NewGuid().ToString("N") + ".json");
    HostPolicyStore.FilePathOverride = policyFile;
    var server = new ProtectionPipeServer(new ScanOrchestrator(new FakeClam(), new FakeYara()), pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var response = await client.SendAsync(new ProtectionPipeRequest
      {
        Operation = ProtectionPipeOperations.SetPolicy,
        RealTimeEnabled = false,
        ProcessMonitorEnabled = false,
        AutoQuarantineEnabled = true,
        SignatureAutoUpdateEnabled = false,
        RemovableDriveScanEnabled = false,
      });

      if (NamedPipeClientAccess.CurrentProcessIsElevatedAdministrator())
        Assert.NotEqual("Non autorisé", response.Message);
      else
      {
        Assert.False(response.Ok);
        Assert.Equal("Non autorisé", response.Message);
        Assert.False(File.Exists(policyFile));
      }
    }
    finally
    {
      HostPolicyStore.FilePathOverride = null;
      await server.StopAsync();
      server.Dispose();
      try { File.Delete(policyFile); } catch { /* déjà absent */ }
    }
  }

  [Fact]
  public async Task Service_quarantine_summary_is_open_but_listing_requires_elevation()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var root = Path.Combine(Path.GetTempPath(), "optiscan_ipc_q_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    var sample = Path.Combine(root, "detected.bin");
    await File.WriteAllBytesAsync(sample, new byte[] { 1, 2, 3 });
    var quarantine = new QuarantineManager(Path.Combine(root, "q"));
    Assert.True(quarantine.Quarantine(new ThreatInfo { FilePath = sample, VirusName = "Ipc.Test", FileSize = 3 }));

    var server = new ProtectionPipeServer(
      new ScanOrchestrator(new FakeClam(), new FakeYara()), pipeName, serviceQuarantine: quarantine);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));

      var summary = await client.GetServiceQuarantineSummaryAsync();
      Assert.True(summary.Ok, summary.Message);
      Assert.Equal(1, summary.Count);
      Assert.Null(summary.Entries);

      var list = await client.ListServiceQuarantineAsync();
      if (!NamedPipeClientAccess.CurrentProcessIsElevatedAdministrator())
      {
        Assert.False(list.Ok);
        Assert.Equal("Non autorisé", list.Message);
        Assert.False((await client.PurgeServiceQuarantineAsync()).Ok);
        Assert.Single(quarantine.GetEntries());
        return;
      }

      var item = Assert.Single(list.Entries!);
      Assert.Equal(sample, item.OriginalPath);

      // Restauration : fichier créé sous le jeton du client, contenu écrit par le service.
      var restored = await client.RestoreServiceQuarantineAsync(item.Id);
      Assert.True(restored.Ok, restored.Message);
      Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(sample));
      Assert.Empty(quarantine.GetEntries());
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
      try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
    }
  }

  [Fact]
  public async Task Service_quarantine_operations_report_unavailable_without_a_store()
  {
    var pipeName = "optiSCAN_Test_" + Guid.NewGuid().ToString("N");
    var server = new ProtectionPipeServer(new ScanOrchestrator(new FakeClam(), new FakeYara()), pipeName);
    server.Start();

    try
    {
      await Task.Delay(200);
      using var client = new ProtectionPipeClient(pipeName, TimeSpan.FromSeconds(10));
      var summary = await client.GetServiceQuarantineSummaryAsync();
      Assert.False(summary.Ok);
      Assert.Equal("Quarantaine du service indisponible", summary.Message);
    }
    finally
    {
      await server.StopAsync();
      server.Dispose();
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
