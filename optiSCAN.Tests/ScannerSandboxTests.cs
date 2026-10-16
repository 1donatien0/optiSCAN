// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>Les tests qui forcent le confinement ne tournent jamais en parallèle des autres.</summary>
[CollectionDefinition("ScannerSandbox", DisableParallelization = true)]
public sealed class ScannerSandboxCollection;

/// <summary>R5 : yara, yarac et clamscan confinés sous SYSTEM.</summary>
[Collection("ScannerSandbox")]
public sealed class ScannerSandboxTests : IDisposable
{
    public void Dispose() => ScannerSandbox.OverrideRequired = null;

    [Theory]
    [InlineData(new string[0], "\"C:\\t\\yara64.exe\"")]
    [InlineData(new[] { "-N" }, "\"C:\\t\\yara64.exe\" -N")]
    [InlineData(new[] { "a b" }, "\"C:\\t\\yara64.exe\" \"a b\"")]
    [InlineData(new[] { "" }, "\"C:\\t\\yara64.exe\" \"\"")]
    [InlineData(new[] { "C:\\dir with space\\" }, "\"C:\\t\\yara64.exe\" \"C:\\dir with space\\\\\"")]
    [InlineData(new[] { "say \"hi\"" }, "\"C:\\t\\yara64.exe\" \"say \\\"hi\\\"\"")]
    [InlineData(new[] { "a\\\\\"b" }, "\"C:\\t\\yara64.exe\" \"a\\\\\\\\\\\"b\"")]
    [InlineData(new[] { "--database=C:\\db" }, "\"C:\\t\\yara64.exe\" --database=C:\\db")]
    public void Command_line_follows_the_CRT_quoting_rules(string[] args, string expected)
    {
        Assert.Equal(expected, ScannerProcess.BuildCommandLine("C:\\t\\yara64.exe", args));
    }

    [Fact]
    public void Command_line_refuses_NUL()
    {
        Assert.Throws<ArgumentException>(() => ScannerProcess.BuildCommandLine("x.exe", new[] { "a\0b" }));
    }

    [Fact]
    public void Command_line_round_trips_through_CommandLineToArgvW()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var args = new[] { "plain", "a b", "", "tail\\", "q\"uote", "x\\\\\"y", "C:\\Program Files\\x\\", "é à" };
        var line = ScannerProcess.BuildCommandLine("C:\\t\\yara64.exe", args);
        var parsed = NativeArgv.Parse(line);
        Assert.Equal(new[] { "C:\\t\\yara64.exe" }.Concat(args), parsed);
    }

    [Fact]
    public void Nothing_is_staged_outside_SYSTEM()
    {
        ScannerSandbox.OverrideRequired = false;
        Assert.False(ScannerSandbox.IsRequired);
        Assert.False(SandboxStaging.NeedsStaging(Path.Combine(Path.GetTempPath(), "x.exe")));
    }

    [Fact]
    public void Under_the_sandbox_only_staging_copies_are_read_directly()
    {
        ScannerSandbox.OverrideRequired = true;
        Assert.True(SandboxStaging.NeedsStaging(Path.Combine(Path.GetTempPath(), "usb", "x.exe")));
        Assert.True(SandboxStaging.NeedsStaging(ScanStaging.Root + "-evil" + Path.DirectorySeparatorChar + "x.exe"));
        Assert.False(SandboxStaging.NeedsStaging(Path.Combine(ScanStaging.Root, "abc", "x.exe")));
    }

    [Fact]
    public void Batches_cover_every_file_once()
    {
        var files = Enumerable.Range(0, SandboxStaging.BatchSize * 2 + 3).Select(i => "f" + i).ToList();
        var batches = SandboxStaging.Batches(files).ToList();
        Assert.Equal(3, batches.Count);
        Assert.All(batches.Take(2), b => Assert.Equal(SandboxStaging.BatchSize, b.Count));
        Assert.Equal(files, batches.SelectMany(b => b));
    }

    [Fact]
    public void Staged_batch_maps_copies_back_and_cleans_up()
    {
        var dir = Directory.CreateTempSubdirectory("optiscan_sbx_").FullName;
        try
        {
            var a = Path.Combine(dir, "a.exe");
            var b = Path.Combine(dir, "b.txt");
            File.WriteAllText(a, "A");
            File.WriteAllText(b, "B");
            var missing = Path.Combine(dir, "missing.bin");

            string stagedA;
            using (var batch = SandboxStaging.Stage(new[] { a, b, missing }, CancellationToken.None))
            {
                Assert.Equal(2, batch.StagedPaths.Count);
                Assert.Equal(new[] { missing }, batch.Skipped);
                stagedA = batch.StagedPaths.Single(p => p.EndsWith("a.exe", StringComparison.OrdinalIgnoreCase));
                Assert.Equal("A", File.ReadAllText(stagedA));
                Assert.Equal(a, batch.OriginalOf(stagedA));
                Assert.Equal("other", batch.OriginalOf("other"));
            }

            Assert.False(File.Exists(stagedA));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ── Windows : le confinement lui-même ─────────────────────────────────────

    private static string Cmd => Path.Combine(Environment.SystemDirectory, "cmd.exe");

    private static (int Exit, string Output, bool Contained) Run(params string[] args)
    {
        var output = new System.Text.StringBuilder();
        using var process = ScannerProcess.Start(new ScannerLaunch(Cmd, args)
        {
            OnOutput = line => { if (line != null) lock (output) output.AppendLine(line); },
            OnError = line => { if (line != null) lock (output) output.AppendLine(line); },
        });
        Assert.True(process.WaitForExitAsync(CancellationToken.None).Wait(TimeSpan.FromSeconds(30)));
        return (process.ExitCode, output.ToString(), process.IsContained);
    }

    [Fact]
    public void Contained_scanner_runs_and_returns_its_output()
    {
        if (!OperatingSystem.IsWindows())
            return;
        ScannerSandbox.OverrideRequired = true;

        var (exit, output, contained) = Run("/d", "/c", "echo optiscan-sandbox");

        Assert.True(contained);
        Assert.Equal(0, exit);
        Assert.Contains("optiscan-sandbox", output);
    }

    [Fact]
    public void Contained_scanner_cannot_read_a_file_outside_its_grants()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var dir = Directory.CreateTempSubdirectory("optiscan_secret_").FullName;
        try
        {
            var secret = Path.Combine(dir, "secret.txt");
            File.WriteAllText(secret, "top-secret-value");
            ScannerSandbox.OverrideRequired = true;

            var (exit, output, _) = Run("/d", "/c", "type", secret);

            Assert.NotEqual(0, exit);
            Assert.DoesNotContain("top-secret-value", output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Contained_scanner_reads_staging_copies()
    {
        if (!OperatingSystem.IsWindows())
            return;
        ScannerSandbox.OverrideRequired = true;
        using var source = new MemoryStream("staged-content"u8.ToArray());
        using var staged = ScanStaging.Stage(source, "sample.txt");

        var output = new System.Text.StringBuilder();
        using var process = ScannerProcess.Start(new ScannerLaunch(Cmd, new[] { "/d", "/c", "type", staged.Path })
        {
            OnOutput = line => { if (line != null) lock (output) output.AppendLine(line); },
            ReadableDirectories = ScannerSandbox.StagingDirectories(),
        });
        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Equal(0, process.ExitCode);
        Assert.Contains("staged-content", output.ToString());
    }

    [Fact]
    public void Contained_scanner_cannot_start_a_child_process()
    {
        if (!OperatingSystem.IsWindows())
            return;
        ScannerSandbox.OverrideRequired = true;

        var (_, output, _) = Run("/d", "/c", Cmd, "/d", "/c", "echo child-ran");

        Assert.DoesNotContain("child-ran", output);
    }

    [Fact]
    public async Task Contained_scanner_is_terminated_by_Kill()
    {
        if (!OperatingSystem.IsWindows())
            return;
        ScannerSandbox.OverrideRequired = true;

        using var process = ScannerProcess.Start(new ScannerLaunch(Cmd, new[] { "/d", "/c", "pause" }));
        var sw = Stopwatch.StartNew();
        process.Kill();
        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(process.HasExited);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10));
    }

    private static class NativeArgv
    {
        [System.Runtime.InteropServices.DllImport("shell32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string[] Parse(string commandLine)
        {
            var argv = CommandLineToArgvW(commandLine, out var count);
            Assert.NotEqual(IntPtr.Zero, argv);
            try
            {
                var result = new string[count];
                for (var i = 0; i < count; i++)
                {
                    var p = System.Runtime.InteropServices.Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                    result[i] = System.Runtime.InteropServices.Marshal.PtrToStringUni(p)!;
                }
                return result;
            }
            finally
            {
                LocalFree(argv);
            }
        }
    }
}
