// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class SafePathDeleteTests
{
    [Fact]
    public void Delete_removes_a_regular_file()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_del_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "note.txt");
        File.WriteAllText(file, "x");

        try
        {
            SafePathDelete.Delete(file);
            Assert.False(File.Exists(file));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* nettoyage */ }
        }
    }

    [Fact]
    public void Delete_refuses_when_a_parent_directory_is_a_reparse_point()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_link_" + Guid.NewGuid().ToString("N"));
        var victimDir = Path.Combine(root, "victim");
        var box = Path.Combine(root, "box");
        Directory.CreateDirectory(victimDir);
        Directory.CreateDirectory(box);
        var secret = Path.Combine(victimDir, "secret.txt");
        File.WriteAllText(secret, "keep");
        var link = Path.Combine(box, "jump");

        try
        {
            if (!CreateSymbolicLink(link, victimDir, SymbolicLinkFlagDirectory | SymbolicLinkFlagAllowUnprivilegedCreate))
                return;

            var viaLink = Path.Combine(link, "secret.txt");
            Assert.Throws<IOException>(() => SafePathDelete.Delete(viaLink));
            Assert.True(File.Exists(secret));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* nettoyage */ }
        }
    }

    [Fact]
    public void Delete_refuses_a_hard_link_and_keeps_both_names()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_hard_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var original = Path.Combine(dir, "original.txt");
        var alias = Path.Combine(dir, "alias.txt");
        File.WriteAllText(original, "keep");

        try
        {
            Assert.True(CreateHardLink(alias, original, IntPtr.Zero),
                "CreateHardLink a échoué : " + Marshal.GetLastWin32Error());

            Assert.Null(SafePathDelete.OpenForQuarantine(alias));
            Assert.Throws<IOException>(() => SafePathDelete.Delete(alias));
            Assert.Throws<IOException>(() => SafePathDelete.Delete(original));
            Assert.Equal("keep", File.ReadAllText(original));
            Assert.Equal("keep", File.ReadAllText(alias));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* nettoyage */ }
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);

    private const int SymbolicLinkFlagDirectory = 1;
    private const int SymbolicLinkFlagAllowUnprivilegedCreate = 2;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateSymbolicLink(string link, string target, int flags);
}
