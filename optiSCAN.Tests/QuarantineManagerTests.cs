// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class QuarantineManagerTests
{
    [Fact]
    public void Quarantine_then_Restore_roundtrip_preserves_content()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_ut_q_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "sample.bin");
        Directory.CreateDirectory(root);

        try
        {
            var payload = new byte[] { 1, 2, 3, 4, 5, 0x5A };
            File.WriteAllBytes(sample, payload);

            var qm = new QuarantineManager(qDir);
            var threat = new ThreatInfo
            {
                FilePath = sample,
                VirusName = "UnitTest",
                FileSize = payload.Length,
                DetectedAt = DateTime.UtcNow,
            };

            Assert.True(qm.Quarantine(threat));
            Assert.False(File.Exists(sample));

            var entries = qm.GetEntries();
            Assert.Single(entries);
            var id = entries[0].Id;

            Assert.True(qm.Restore(id));
            Assert.True(File.Exists(sample));
            Assert.Equal(payload, File.ReadAllBytes(sample));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void GetEntriesPaged_empty_returns_empty()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_ut_qp_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "q");
        try
        {
            var qm = new QuarantineManager(qDir);
            Assert.Empty(qm.GetEntriesPaged(0, 10));
            Assert.Empty(qm.GetEntriesPaged(0, 0));
            Assert.Empty(qm.GetEntriesPaged(5, 10));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void GetEntriesPaged_returns_window()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_ut_qw_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "q");
        Directory.CreateDirectory(root);
        try
        {
            var qm = new QuarantineManager(qDir);
            for (int i = 0; i < 3; i++)
            {
                var f = Path.Combine(root, $"f{i}.txt");
                File.WriteAllText(f, $"x{i}");
                Assert.True(qm.Quarantine(new ThreatInfo
                {
                    FilePath = f,
                    VirusName = "T",
                    FileSize = new FileInfo(f).Length,
                    DetectedAt = DateTime.UtcNow,
                }));
            }

            Assert.Equal(3, qm.Count);
            var page = qm.GetEntriesPaged(1, 1);
            Assert.Single(page);
            Assert.Contains("f1.txt", page[0].OriginalPath, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Mise à jour v1 → v2 : le HMAC du manifeste est calculé sur la sérialisation des
    /// entrées. Une entrée sans session d'origine doit se sérialiser exactement comme en
    /// version 1 (pas de clé SourceSessionId), sinon la quarantaine v1 est rejetée.
    /// </summary>
    [Fact]
    public void QuarantineEntry_without_session_serializes_like_v1_for_manifest_hmac()
    {
        var entry = new QuarantineEntry
        {
            Id = "abc",
            OriginalPath = @"C:\temp\x.exe",
            QuarantinePath = @"C:\q\abc.qbin",
            VirusName = "Eicar",
            QuarantinedAt = new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc),
            OriginalSize = 68,
            Sha256 = "00",
        };

        var legacyJson = System.Text.Json.JsonSerializer.Serialize(new List<QuarantineEntry> { entry });
        Assert.DoesNotContain("SourceSessionId", legacyJson);

        entry.SourceSessionId = Guid.NewGuid();
        var v2Json = System.Text.Json.JsonSerializer.Serialize(new List<QuarantineEntry> { entry });
        Assert.Contains("SourceSessionId", v2Json);

        var roundTrip = System.Text.Json.JsonSerializer.Deserialize<List<QuarantineEntry>>(v2Json)!;
        Assert.Equal(entry.SourceSessionId, roundTrip[0].SourceSessionId);
    }
}
