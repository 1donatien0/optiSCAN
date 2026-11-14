// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class SecureStoreTests
{
    private sealed class TestDto
    {
        public string Value { get; set; } = "";
        public int N { get; set; }
    }

    [Fact]
    public void Save_Load_roundtrip_restores_payload()
    {
        var path = Path.Combine(Path.GetTempPath(), "optiscan_ut_secure_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            var original = new TestDto { Value = "roundtrip-payload", N = 42 };
            SecureStore.Save(path, original);

            var loaded = SecureStore.Load<TestDto>(path);
            Assert.NotNull(loaded);
            Assert.Equal("roundtrip-payload", loaded.Value);
            Assert.Equal(42, loaded.N);
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Load_corrupted_blob_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), "optiscan_ut_corrupt_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            var original = new TestDto { Value = "x", N = 1 };
            SecureStore.Save(path, original);

            var bytes = File.ReadAllBytes(path);
            if (bytes.Length > 4)
                bytes[^1] ^= 0xFF;
            File.WriteAllBytes(path, bytes);

            Assert.Null(SecureStore.Load<TestDto>(path));
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Load_unsigned_envelope_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), "optiscan_ut_unsigned_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            var envelope = Encoding.UTF8.GetBytes("{\"Json\":\"{\\\"Value\\\":\\\"x\\\",\\\"N\\\":1}\"}");
            var encrypted = ProtectedData.Protect(envelope, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(path, encrypted);

            Assert.Null(SecureStore.Load<TestDto>(path));
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void TrySave_returns_false_when_new_key_cannot_be_persisted()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_ut_keyfail_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var keyPath = Path.Combine(dir, "hmac.key");
        var dataPath = Path.Combine(dir, "prefs.dat");
        SecureStore.HmacKeyPathOverrideForTests = keyPath;
        SecureStore.PersistNewKeyForTests = (_, _) => throw new IOException("écriture de clé simulée");
        try
        {
            Assert.False(SecureStore.TrySave(dataPath, new TestDto { Value = "ne-pas-ecrire", N = 1 }));
            Assert.False(File.Exists(dataPath));
            Assert.False(File.Exists(keyPath));
        }
        finally
        {
            SecureStore.PersistNewKeyForTests = null;
            SecureStore.HmacKeyPathOverrideForTests = null;
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Save_reports_failure_when_new_key_cannot_be_persisted()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_ut_savefail_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        SecureStore.HmacKeyPathOverrideForTests = Path.Combine(dir, "hmac.key");
        SecureStore.PersistNewKeyForTests = (_, _) => throw new IOException("écriture de clé simulée");
        try
        {
            Assert.False(SecureStore.Save(Path.Combine(dir, "prefs.dat"), new TestDto { Value = "x", N = 1 }));

            SecureStore.PersistNewKeyForTests = null;
            Assert.True(SecureStore.Save(Path.Combine(dir, "prefs.dat"), new TestDto { Value = "x", N = 1 }));
        }
        finally
        {
            SecureStore.PersistNewKeyForTests = null;
            SecureStore.HmacKeyPathOverrideForTests = null;
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Save_Load_still_works_after_a_failed_key_persist()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_ut_keyok_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var keyPath = Path.Combine(dir, "hmac.key");
        var dataPath = Path.Combine(dir, "prefs.dat");
        SecureStore.HmacKeyPathOverrideForTests = keyPath;
        try
        {
            SecureStore.PersistNewKeyForTests = (_, _) => throw new IOException("écriture de clé simulée");
            Assert.False(SecureStore.TrySave(dataPath, new TestDto { Value = "rate", N = 0 }));

            SecureStore.PersistNewKeyForTests = null;
            Assert.True(SecureStore.TrySave(dataPath, new TestDto { Value = "ok", N = 7 }));
            var loaded = SecureStore.Load<TestDto>(dataPath);
            Assert.NotNull(loaded);
            Assert.Equal("ok", loaded.Value);
            Assert.Equal(7, loaded.N);
        }
        finally
        {
            SecureStore.PersistNewKeyForTests = null;
            SecureStore.HmacKeyPathOverrideForTests = null;
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
