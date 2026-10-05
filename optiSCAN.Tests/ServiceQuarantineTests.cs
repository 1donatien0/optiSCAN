using optiSCAN.Models;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>Quarantaine du service : emplacement, migration, conservation, opérations d'administration.</summary>
public sealed class ServiceQuarantineTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "optiscan_sq_" + Guid.NewGuid().ToString("N"));

    public ServiceQuarantineTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    private string Sample(string name, byte[] content)
    {
        var path = Path.Combine(_root, "files", name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return path;
    }

    private static ThreatInfo Threat(string path, long size) => new()
    {
        FilePath = path,
        VirusName = "UnitTest.Service",
        FileSize = size,
        DetectedAt = DateTime.UtcNow,
    };

    /// <summary>Crée le fichier comme le ferait le client du pipe : jamais d'écrasement.</summary>
    private static IRestoreTarget? CreateNew(string path)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            return new FileTarget(path, new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None));
        }
        catch (IOException)
        {
            return null;
        }
    }

    private sealed class FileTarget(string path, FileStream stream) : IRestoreTarget
    {
        private bool _discard;

        public Stream Stream => stream;
        public string FinalPath => path;
        public void Discard() => _discard = true;

        public void Dispose()
        {
            stream.Dispose();
            if (_discard)
                File.Delete(path);
        }
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789ABCDEF", true)]
    [InlineData("0123456789abcdef0123456789abcde", false)]
    [InlineData("..\\..\\Windows\\System32\\x.dll00", false)]
    [InlineData(null, false)]
    public void IsValidId_accepts_only_32_hex_characters(string? id, bool expected) =>
        Assert.Equal(expected, ServiceQuarantineAdmin.IsValidId(id));

    [Fact]
    public void CandidateNames_never_reuse_the_original_name_twice()
    {
        var names = ServiceQuarantineAdmin.CandidateNames(Path.Combine(_root, "doc.pdf")).ToList();

        Assert.Equal(Path.Combine(_root, "doc.pdf"), names[0]);
        Assert.Equal(Path.Combine(_root, "doc_restored.pdf"), names[1]);
        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void MigrateLegacy_without_legacy_manifest_does_nothing()
    {
        var legacy = Path.Combine(_root, "legacy");
        var target = Path.Combine(_root, "target");
        Directory.CreateDirectory(legacy);

        Assert.False(ServiceQuarantineStore.MigrateLegacy(legacy, target));
        Assert.False(Directory.Exists(target));
    }

    [Fact]
    public void MigrateLegacy_keeps_both_when_the_target_already_has_a_manifest()
    {
        var legacy = Path.Combine(_root, "legacy");
        var target = Path.Combine(_root, "target");
        Directory.CreateDirectory(legacy);
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(legacy, "manifest.json"), "{}");
        File.WriteAllText(Path.Combine(target, "manifest.json"), "{}");

        Assert.False(ServiceQuarantineStore.MigrateLegacy(legacy, target));
        Assert.True(File.Exists(Path.Combine(legacy, "manifest.json")));
    }

    [Fact]
    public void MigrateLegacy_moves_the_store_and_entries_stay_restorable()
    {
        var legacy = Path.Combine(_root, "legacy");
        var target = Path.Combine(_root, "programdata", "Quarantine");
        var payload = new byte[] { 7, 8, 9, 0x5A };
        var sample = Sample("moved.bin", payload);

        var before = new QuarantineManager(legacy);
        Assert.True(before.Quarantine(Threat(sample, payload.Length)));
        var id = before.GetEntries()[0].Id;

        Assert.True(ServiceQuarantineStore.MigrateLegacy(legacy, target));
        Assert.False(Directory.Exists(legacy));

        var after = new QuarantineManager(target);
        var entry = Assert.Single(after.GetEntries());
        Assert.StartsWith(target, entry.QuarantinePath, StringComparison.OrdinalIgnoreCase);

        var response = new ServiceQuarantineAdmin(after).Restore(id, null, CreateNew);
        Assert.True(response.Ok, response.Message);
        Assert.Equal(payload, File.ReadAllBytes(sample));
        Assert.Empty(after.GetEntries());
    }

    [Fact]
    public void Restore_never_overwrites_an_existing_file()
    {
        var payload = new byte[] { 1, 2, 3 };
        var sample = Sample("report.docx", payload);
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        Assert.True(qm.Quarantine(Threat(sample, payload.Length)));
        var id = qm.GetEntries()[0].Id;

        // Un autre fichier a pris le nom entre-temps.
        File.WriteAllBytes(sample, new byte[] { 42 });

        var response = new ServiceQuarantineAdmin(qm).Restore(id, null, CreateNew);

        Assert.True(response.Ok, response.Message);
        Assert.Equal(new byte[] { 42 }, File.ReadAllBytes(sample));
        var restored = Path.Combine(Path.GetDirectoryName(sample)!, "report_restored.docx");
        Assert.Equal(restored, response.Message);
        Assert.Equal(payload, File.ReadAllBytes(restored));
    }

    [Fact]
    public void Restore_to_a_chosen_folder_uses_the_original_file_name()
    {
        var payload = new byte[] { 4, 5, 6 };
        var sample = Sample("tool.exe", payload);
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        Assert.True(qm.Quarantine(Threat(sample, payload.Length)));
        var id = qm.GetEntries()[0].Id;
        var folder = Path.Combine(_root, "restored-here");

        var response = new ServiceQuarantineAdmin(qm).Restore(id, folder, CreateNew);

        Assert.True(response.Ok, response.Message);
        Assert.Equal(payload, File.ReadAllBytes(Path.Combine(folder, "tool.exe")));
        Assert.False(File.Exists(sample));
    }

    [Fact]
    public void Restore_refuses_a_relative_or_system_destination_and_keeps_the_entry()
    {
        var payload = new byte[] { 9 };
        var sample = Sample("x.bin", payload);
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        Assert.True(qm.Quarantine(Threat(sample, payload.Length)));
        var id = qm.GetEntries()[0].Id;
        var admin = new ServiceQuarantineAdmin(qm);
        var created = 0;
        IRestoreTarget? Spy(string p) { created++; return CreateNew(p); }

        Assert.False(admin.Restore(id, "relative\\dir", Spy).Ok);
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (!string.IsNullOrEmpty(system))
            Assert.False(admin.Restore(id, system, Spy).Ok);

        Assert.Equal(0, created);
        Assert.Single(qm.GetEntries());
    }

    [Fact]
    public void Restore_discards_the_file_when_nothing_can_be_created()
    {
        var payload = new byte[] { 3, 1, 4 };
        var sample = Sample("y.bin", payload);
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        Assert.True(qm.Quarantine(Threat(sample, payload.Length)));
        var id = qm.GetEntries()[0].Id;

        var response = new ServiceQuarantineAdmin(qm).Restore(id, null, _ => null);

        Assert.False(response.Ok);
        Assert.Single(qm.GetEntries());
    }

    [Fact]
    public void Delete_and_purge_validate_identifiers_and_remove_entries()
    {
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        var a = Sample("a.bin", new byte[] { 1 });
        var b = Sample("b.bin", new byte[] { 2 });
        Assert.True(qm.Quarantine(Threat(a, 1)));
        Assert.True(qm.Quarantine(Threat(b, 1)));
        var admin = new ServiceQuarantineAdmin(qm);

        Assert.False(admin.Delete("not-an-id").Ok);
        Assert.False(admin.Delete(new string('0', 32)).Ok);
        Assert.True(admin.Delete(qm.GetEntries()[0].Id).Ok);
        Assert.Single(qm.GetEntries());

        var purge = admin.Purge();
        Assert.True(purge.Ok);
        Assert.Equal(1, purge.Count);
        Assert.Empty(qm.GetEntries());
    }

    [Fact]
    public void List_and_summary_report_count_size_and_retention()
    {
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        var a = Sample("a.bin", new byte[] { 1, 2 });
        Assert.True(qm.Quarantine(Threat(a, 2)));
        var admin = new ServiceQuarantineAdmin(qm);

        var summary = admin.Summary();
        Assert.Equal(1, summary.Count);
        Assert.Equal(2, summary.TotalBytes);
        Assert.Equal(ServiceQuarantineStore.RetentionDays, summary.RetentionDays);
        Assert.Null(summary.Entries);

        var list = admin.List();
        var item = Assert.Single(list.Entries!);
        Assert.Equal(a, item.OriginalPath);
        Assert.Equal("UnitTest.Service", item.VirusName);
    }

    [Fact]
    public void PurgeOlderThan_removes_only_expired_entries()
    {
        var qm = new QuarantineManager(Path.Combine(_root, "q"));
        Assert.True(qm.Quarantine(Threat(Sample("old.bin", new byte[] { 1 }), 1)));

        Assert.Equal(0, qm.PurgeOlderThan(DateTime.Now.AddDays(-ServiceQuarantineStore.RetentionDays)));
        Assert.Single(qm.GetEntries());

        Assert.Equal(1, qm.PurgeOlderThan(DateTime.Now.AddMinutes(1)));
        Assert.Empty(qm.GetEntries());
    }
}
