// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class SystemTweaksServiceTests
{
    private static IEnumerable<SystemTweaksService.ElevatedCommand> AllElevatedCommands() =>
        SystemTweaksService.ElevatedTelemetryCommands()
            .Concat(SystemTweaksService.ElevatedDismCleanupCommands())
            .Append(SystemTweaksService.StopWindowsUpdateCommand)
            .Append(SystemTweaksService.StartWindowsUpdateCommand);

    [Fact]
    public void Elevated_commands_call_system_tools_directly_without_cmd()
    {
        foreach (var command in AllElevatedCommands())
        {
            Assert.NotEqual("cmd.exe", command.Tool, StringComparer.OrdinalIgnoreCase);
            Assert.Equal(Environment.SystemDirectory, Path.GetDirectoryName(command.FilePath));
            // ArgumentList échappe les guillemets en \" : aucun argument ne doit en contenir,
            // ni de syntaxe propre à cmd (%%d, &, |).
            Assert.All(command.Arguments, argument =>
            {
                Assert.DoesNotContain('"', argument);
                Assert.DoesNotContain('%', argument);
                Assert.DoesNotContain('&', argument);
                Assert.DoesNotContain('|', argument);
            });
        }
    }

    [Fact]
    public void Telemetry_policy_key_is_passed_as_a_single_unquoted_argument()
    {
        var reg = SystemTweaksService.ElevatedTelemetryCommands().First();

        Assert.Equal("reg.exe", reg.Tool);
        Assert.Equal(
            new[] { "add", @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "/v", "AllowTelemetry", "/t", "REG_DWORD", "/d", "0", "/f" },
            reg.Arguments);
    }

    [Fact]
    public void Stopping_an_already_stopped_service_is_not_a_failure()
    {
        Assert.Contains(1062, SystemTweaksService.StopWindowsUpdateCommand.AcceptedExitCodes);
        Assert.Contains(1056, SystemTweaksService.StartWindowsUpdateCommand.AcceptedExitCodes);
    }

    [Fact]
    public void Defender_history_clearing_is_no_longer_an_elevated_action()
    {
        Assert.DoesNotContain("defender-history", SystemTweaksService.KnownElevatedTweakIds);
        // Un ancien identifiant reçu par --apply-tweaks est ignoré, rien n'est lancé.
        Assert.True(SystemTweaksService.ExecuteTweakIds(new[] { "defender-history" }));
    }

    [Fact]
    public void ClearDirectoryContents_empties_the_folder_without_following_links()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_tweaks_" + Guid.NewGuid().ToString("N"));
        var cache = Path.Combine(root, "Download");
        var outside = Path.Combine(root, "outside");
        Directory.CreateDirectory(Path.Combine(cache, "sub"));
        Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(cache, "a.bin"), "a");
        File.WriteAllText(Path.Combine(cache, "sub", "b.bin"), "b");
        var kept = Path.Combine(outside, "keep.txt");
        File.WriteAllText(kept, "keep");

        var linkCreated = false;
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(cache, "link"), outside);
            linkCreated = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Création de lien refusée (Windows sans mode développeur) : le reste est vérifié.
        }

        try
        {
            Assert.True(SystemTweaksService.ClearDirectoryContents(cache));

            Assert.True(Directory.Exists(cache));
            Assert.Empty(Directory.EnumerateFileSystemEntries(cache));
            if (linkCreated)
                Assert.True(File.Exists(kept));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ClearDirectoryContents_accepts_a_missing_folder()
    {
        var missing = Path.Combine(Path.GetTempPath(), "optiscan_absent_" + Guid.NewGuid().ToString("N"));
        Assert.True(SystemTweaksService.ClearDirectoryContents(missing));
    }
}
