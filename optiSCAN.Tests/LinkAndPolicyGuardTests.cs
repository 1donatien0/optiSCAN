// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Politique déposée avant la reprise de ProgramData, jonctions dans les dossiers du temps réel,
/// et quarantaine qui lit puis supprime par un seul accès.
/// Les cas qui créent des liens ne tournent que sur Windows, et seulement si le compte
/// peut créer un lien symbolique (mode développeur ou administrateur).
/// </summary>
public sealed class LinkAndPolicyGuardTests
{
    [Fact]
    public void A_file_owned_by_the_user_is_not_trusted_as_ProgramData_content()
    {
        var file = Path.Combine(Path.GetTempPath(), "optiscan_ut_policy_" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(file, "{\"RealTimeEnabled\":false,\"AutoQuarantineEnabled\":true}");
        try
        {
            Assert.False(OptiScanProgramData.IsTrustedFile(file));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Theory]
    [InlineData(@"\\?\C:\Users\a\Downloads\x.exe", @"\\?\C:\Users\a\Downloads", true)]
    [InlineData(@"\\?\C:\Users\a\Downloads\sub\x.exe", @"\\?\c:\users\a\downloads\", true)]
    [InlineData(@"\\?\C:\Users\a\Downloads2\x.exe", @"\\?\C:\Users\a\Downloads", false)]
    [InlineData(@"\\?\C:\Users\b\secret.docx", @"\\?\C:\Users\a\Downloads", false)]
    [InlineData(@"\\?\C:\Users\a\Downloads", @"\\?\C:\Users\a\Downloads", false)]
    public void Real_path_must_stay_under_the_watched_folder(string path, string root, bool expected) =>
        Assert.Equal(expected, RealTimePathGuard.IsUnder(path, root));

    [Fact]
    public void A_file_reached_through_a_link_inside_a_watched_folder_is_not_scanned()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var root = NewDir("watch");
        var outside = NewDir("outside");
        var target = Path.Combine(outside, "private.exe");
        File.WriteAllBytes(target, new byte[] { 0x4D, 0x5A });
        var direct = Path.Combine(root, "direct.exe");
        File.WriteAllBytes(direct, new byte[] { 0x4D, 0x5A });
        try
        {
            using (var pin = RealTimePathGuard.PinWithinRoot(root, direct, out _))
                Assert.NotNull(pin);

            if (!TryLink(Path.Combine(root, "link"), outside))
                return;

            Assert.Null(RealTimePathGuard.PinWithinRoot(root, Path.Combine(root, "link", "private.exe"), out var refusal));
            Assert.Contains("jonction", refusal);
            Assert.False(RealTimePathGuard.IsDirectPath(Path.Combine(root, "link")));
            Assert.True(RealTimePathGuard.IsDirectPath(root));
        }
        finally
        {
            Cleanup(root, outside);
        }
    }

    [Fact]
    public void A_hard_link_inside_a_watched_folder_is_not_scanned()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var root = NewDir("hardwatch");
        var outside = NewDir("hardout");
        var target = Path.Combine(outside, "secret.exe");
        File.WriteAllBytes(target, new byte[] { 0x4D, 0x5A, 1 });
        var alias = Path.Combine(root, "alias.exe");
        try
        {
            Assert.True(CreateHardLink(alias, target, IntPtr.Zero),
                "CreateHardLink a échoué : " + Marshal.GetLastWin32Error());

            Assert.Null(RealTimePathGuard.PinWithinRoot(root, alias, out var refusal));
            Assert.Equal("lien physique", refusal);
            Assert.False(RealTimePathGuard.IsExecutableWithinRoot(root, alias));
            Assert.Equal(new byte[] { 0x4D, 0x5A, 1 }, File.ReadAllBytes(target));
            Assert.True(File.Exists(alias));
        }
        finally
        {
            Cleanup(root, outside);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);

    [Fact]
    public void While_pinned_for_a_scan_the_file_cannot_be_swapped()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var root = NewDir("pin");
        var file = Path.Combine(root, "a.exe");
        File.WriteAllBytes(file, new byte[] { 1 });
        try
        {
            using (RealTimePathGuard.PinWithinRoot(root, file, out _))
                Assert.ThrowsAny<IOException>(() => File.Move(file, file + ".old"));

            File.Move(file, file + ".old");
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void Quarantine_handle_reads_and_deletes_the_same_file_and_locks_its_name()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var root = NewDir("quar");
        var file = Path.Combine(root, "x.bin");
        File.WriteAllBytes(file, new byte[] { 1, 2, 3 });
        try
        {
            using (var handle = SafePathDelete.OpenForQuarantine(file))
            {
                Assert.NotNull(handle);
                Assert.Equal(3, handle!.Length);
                var buffer = new byte[3];
                Assert.True(handle.TryReadAll(buffer));
                Assert.Equal(new byte[] { 1, 2, 3 }, buffer);

                // Le nom ne peut pas être remplacé entre la lecture et la suppression.
                Assert.ThrowsAny<IOException>(() => File.Move(file, file + ".old"));
                Assert.ThrowsAny<IOException>(() => File.WriteAllBytes(file, new byte[] { 9 }));

                Assert.True(handle.MarkForDelete());
                Assert.True(handle.CancelDelete());
            }

            Assert.True(File.Exists(file));

            using (var handle = SafePathDelete.OpenForQuarantine(file))
                Assert.True(handle!.MarkForDelete());
            Assert.False(File.Exists(file));
        }
        finally
        {
            Cleanup(root);
        }
    }

    [Fact]
    public void Quarantine_handle_refuses_a_link_in_place_of_the_file_or_a_parent()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var root = NewDir("quarlink");
        var outside = NewDir("quarout");
        var target = Path.Combine(outside, "keep.txt");
        File.WriteAllText(target, "keep");
        try
        {
            if (!TryLink(Path.Combine(root, "dir"), outside))
                return;

            Assert.Null(SafePathDelete.OpenForQuarantine(Path.Combine(root, "dir", "keep.txt")));

            var fileLink = Path.Combine(root, "file.txt");
            try
            {
                File.CreateSymbolicLink(fileLink, target);
                Assert.Null(SafePathDelete.OpenForQuarantine(fileLink));
            }
            catch (UnauthorizedAccessException)
            {
                /* lien fichier refusé : partie ignorée */
            }

            Assert.True(File.Exists(target));
        }
        finally
        {
            Cleanup(root, outside);
        }
    }

    private static string NewDir(string label)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"optiscan_ut_{label}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static bool TryLink(string link, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(link, target);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void Cleanup(params string[] dirs)
    {
        foreach (var dir in dirs)
        {
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
                {
                    if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) == 0)
                        continue;
                    if (Directory.Exists(entry))
                        Directory.Delete(entry);
                    else
                        File.Delete(entry);
                }

                Directory.Delete(dir, recursive: true);
            }
            catch
            {
                /* best effort */
            }
        }
    }
}
