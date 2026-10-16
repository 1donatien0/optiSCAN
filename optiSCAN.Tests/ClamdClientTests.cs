// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ClamdClientTests
{
    [Fact]
    public async Task PingAsync_returns_true_on_PONG()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = listener.AcceptTcpClientAsync();

        using var client = new ClamdClient("127.0.0.1", port);
        var pingTask = client.PingAsync();

        var server = await accept;
        await using var stream = server.GetStream();
        var buffer = new byte[64];
        int read = await stream.ReadAsync(buffer);
        var cmd = Encoding.UTF8.GetString(buffer, 0, read).Trim();
        Assert.Equal("PING", cmd);

        var pong = Encoding.UTF8.GetBytes("PONG\n");
        await stream.WriteAsync(pong);

        Assert.True(await pingTask);
        listener.Stop();
    }

    [Fact]
    public async Task ScanRecursiveAsync_waits_past_400ms_for_the_first_line()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = listener.AcceptTcpClientAsync();

        using var client = new ClamdClient("127.0.0.1", port);
        var scanTask = client.ScanRecursiveAsync(@"C:\temp");

        var server = await accept;
        await using var stream = server.GetStream();
        var buffer = new byte[256];
        _ = await stream.ReadAsync(buffer);
        await Task.Delay(700);
        var line = Encoding.UTF8.GetBytes(@"C:\temp\eicar.com: Eicar-Test-Signature FOUND" + "\n");
        await stream.WriteAsync(line);
        server.Client.Shutdown(SocketShutdown.Send);

        var result = await scanTask;
        Assert.True(result.Completed);
        Assert.Contains("FOUND", result.Text, StringComparison.Ordinal);
        listener.Stop();
    }

    [Fact]
    public async Task Broker_relays_ping_without_opening_clamd_to_the_caller()
    {
        var pipe = "optiSCAN_TestClamd_" + Guid.NewGuid().ToString("N");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var served = new TaskCompletionSource<bool>();

        var accept = Task.Run(async () =>
        {
            using var tcp = await listener.AcceptTcpClientAsync();
            await using var stream = tcp.GetStream();
            var buffer = new byte[32];
            var read = await stream.ReadAsync(buffer);
            Assert.Equal("PING", Encoding.UTF8.GetString(buffer, 0, read).Trim());
            await stream.WriteAsync(Encoding.UTF8.GetBytes("PONG\n"));
            served.TrySetResult(true);
        });

        using var stop = new CancellationTokenSource();
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? "S-1-5-18";
        var broker = ClamdBroker.RunAsync(pipe, port, parentPid: 0, sid, stop.Token);

        using var client = ClamdClient.ForPipe(pipe);
        Assert.True(await client.PingAsync());
        await served.Task.WaitAsync(TimeSpan.FromSeconds(5));
        stop.Cancel();
        listener.Stop();
        try { await broker.WaitAsync(TimeSpan.FromSeconds(3)); } catch { /* arrêt du relais */ }
        await accept;
    }

    [Fact]
    public void Isolated_process_starts_in_an_appcontainer()
    {
        var work = Path.GetDirectoryName(typeof(ClamdClientTests).Assembly.Location)!;
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var process = ClamdIsolation.Start(cmd, "/k", work, network: false, writableDirectories: new[] { work });
        Assert.NotNull(process);
        try
        {
            Assert.False(process!.WaitForExit(800));
            Assert.True(ClamdIsolation.IsInAppContainer(process));
        }
        finally
        {
            try { process?.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
            ClamdIsolation.Release(process);
        }
    }

    [Fact]
    public async Task Clamd_relay_is_reachable_through_the_named_pipe()
    {
        var exe = FindOptiScanExe();
        Assert.False(string.IsNullOrEmpty(exe));
        var work = Path.GetDirectoryName(exe)!;
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        var pipe = "optiSCAN_Iso_" + Guid.NewGuid().ToString("N");
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        Assert.False(string.IsNullOrEmpty(sid));
        var previous = Environment.GetEnvironmentVariable("OPTISCAN_CLAMD_STUB");
        Environment.SetEnvironmentVariable("OPTISCAN_CLAMD_STUB", "1");
        using var stop = new CancellationTokenSource();
        var controlFile = Path.Combine(work, "relay-handles.txt");
        using var channel = ClamdRelayChannel.Create(sid!, controlFile);
        Assert.NotNull(channel);
        Process? stub = null;
        Process? broker = null;
        Task? serve = null;
        try
        {
            stub = ClamdIsolation.Start(exe!, "--clamd-stub " + port.ToString(), work, network: true, writableDirectories: new[] { work });
            broker = ClamdIsolation.Start(
                exe!,
                "--clamd-relay " + port.ToString() + " " + Environment.ProcessId.ToString() + " \"" + controlFile + "\"",
                work,
                network: true,
                writableDirectories: new[] { work });
            Assert.NotNull(stub);
            Assert.NotNull(broker);
            serve = ClamdBroker.ServeAsync(pipe, sid!, () => channel.OpenData(broker!), stop.Token);

            var relayed = false;
            for (var i = 0; i < 4 && !relayed; i++)
            {
                if (stub!.HasExited || broker!.HasExited || serve!.IsCompleted)
                    break;
                try
                {
                    using var client = ClamdClient.ForPipe(pipe, connectTimeoutMs: 1000);
                    using var pingWait = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                    relayed = await client.PingAsync(pingWait.Token);
                }
                catch
                {
                    relayed = false;
                }
                if (!relayed)
                    await Task.Delay(300);
            }

            Assert.True(relayed);
            // Les sondes TCP directes dépendent des filtres loopback du poste;
            // le test vérifie le transport supporté par optiSCAN, le tube ACL.
        }
        finally
        {
            stop.Cancel();
            if (serve != null)
            {
                try { await serve.WaitAsync(TimeSpan.FromSeconds(3)); } catch { /* arrêt du serveur */ }
            }
            Environment.SetEnvironmentVariable("OPTISCAN_CLAMD_STUB", previous);
            try { broker?.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
            try { stub?.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
            ClamdIsolation.Release(broker);
            ClamdIsolation.Release(stub);
        }
    }

    private static string? FindOptiScanExe()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            foreach (var config in new[] { "Debug", "Release" })
            {
                foreach (var candidate in new[]
                {
                    Path.Combine(dir.FullName, "optiSCAN", "bin", config, "net10.0-windows10.0.17763.0", "optiSCAN.exe"),
                    Path.Combine(dir.FullName, "optiSCAN", config, "net10.0-windows10.0.17763.0", "optiSCAN.exe"),
                    Path.Combine(dir.FullName, "optiSCAN.exe"),
                })
                {
                    if (File.Exists(candidate))
                        return candidate;
                }
            }
            dir = dir.Parent;
        }
        return null;
    }
}
