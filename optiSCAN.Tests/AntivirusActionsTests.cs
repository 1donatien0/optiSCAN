using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class AntivirusActionsTests
{
    [Fact]
    public void DeleteThreatFile_deletes_existing_file_on_disk()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_del_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "threat.bin");
        File.WriteAllBytes(file, [0x4D, 0x5A]);

        try
        {
            var actions = new AntivirusActions(ServiceContainer.Default);
            var result = actions.DeleteThreatFile(file);

            Assert.True(result.Success);
            Assert.False(File.Exists(file));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void DeleteThreatFile_refuses_sensitive_system_path()
    {
        var actions = new AntivirusActions(ServiceContainer.Default);
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "optiscan_delete_test_should_not_run.exe");

        var result = actions.DeleteThreatFile(path);

        Assert.False(result.Success);
        Assert.True(result.IsError);
    }

    [Fact]
    public void DeleteThreatFile_reports_missing_when_file_already_gone()
    {
        var actions = new AntivirusActions(ServiceContainer.Default);
        var path = Path.Combine(Path.GetTempPath(), "optiscan_missing_" + Guid.NewGuid().ToString("N") + ".bin");

        var result = actions.DeleteThreatFile(path);

        Assert.False(result.Success);
    }

    [Fact]
    public void QuarantineThreat_moves_file_to_quarantine_and_removes_original()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_qact_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "malware.bin");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(sample, [0xDE, 0xAD]);

        try
        {
            var qm = new QuarantineManager(qDir);
            var actions = new AntivirusActions(qm);

            var result = actions.QuarantineThreat(new ThreatInfo
            {
                FilePath = sample,
                VirusName = "Test.Eicar",
                FileSize = 2,
                DetectedAt = DateTime.UtcNow,
            });

            Assert.True(result.Success);
            Assert.False(File.Exists(sample));
            Assert.Single(qm.GetEntries());
            Assert.True(File.Exists(qm.GetEntries()[0].QuarantinePath));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void QuarantineThreat_fails_when_file_missing()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_qmiss_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        Directory.CreateDirectory(root);

        try
        {
            var actions = new AntivirusActions(new QuarantineManager(qDir));
            var missing = Path.Combine(root, "gone.bin");

            var result = actions.QuarantineThreat(missing);

            Assert.False(result.Success);
            Assert.Empty(new QuarantineManager(qDir).GetEntries());
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void IgnoreThreat_adds_file_to_exclusions_without_deleting_it()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_ign_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "keep.me");
        File.WriteAllText(file, "data");

        var actions = new AntivirusActions(ServiceContainer.Default);

        try
        {
            Assert.False(ExclusionSettings.Current.IsFileExcluded(file));

            var result = actions.IgnoreThreat(file);

            Assert.True(result.Success);
            Assert.True(File.Exists(file));
            Assert.True(ExclusionSettings.Current.IsFileExcluded(file));
        }
        finally
        {
            ExclusionSettings.Current.RemoveFile(file);
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void RestoreFromQuarantine_restores_original_content()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_rst_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "restore-me.bin");
        Directory.CreateDirectory(root);
        var payload = new byte[] { 9, 8, 7, 6 };
        File.WriteAllBytes(sample, payload);

        try
        {
            var qm = new QuarantineManager(qDir);
            var actions = new AntivirusActions(qm);
            Assert.True(actions.QuarantineThreat(new ThreatInfo
            {
                FilePath = sample,
                VirusName = "Test",
                FileSize = payload.Length,
            }).Success);

            var id = qm.GetEntries()[0].Id;
            var result = actions.RestoreFromQuarantine(id);

            Assert.True(result.Success);
            Assert.True(File.Exists(sample));
            Assert.Equal(payload, File.ReadAllBytes(sample));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void DeleteFromQuarantine_removes_quarantine_blob()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_qdel_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "blob.bin");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(sample, [1]);

        try
        {
            var qm = new QuarantineManager(qDir);
            var actions = new AntivirusActions(qm);
            Assert.True(actions.QuarantineThreat(new ThreatInfo
            {
                FilePath = sample,
                VirusName = "Test",
                FileSize = 1,
            }).Success);

            var id = qm.GetEntries()[0].Id;
            var qPath = qm.GetEntries()[0].QuarantinePath;

            var result = actions.DeleteFromQuarantine(id);

            Assert.True(result.Success);
            Assert.Empty(qm.GetEntries());
            Assert.False(File.Exists(qPath));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }
}
