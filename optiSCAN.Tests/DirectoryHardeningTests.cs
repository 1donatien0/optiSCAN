using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using optiSCAN.Services;
using Xunit;

namespace optiSCAN.Tests
{
    /// <summary>
    /// Vérifie le durcissement ACL S-1 : l'application conserve l'accès à ses
    /// propres données après restriction, et l'héritage large est bien rompu.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class DirectoryHardeningTests
    {
        [Fact]
        public void HardenDataDirectory_KeepsOwnerAccess_AndBreaksInheritance()
        {
            if (!OperatingSystem.IsWindows())
                return; // ACL Windows uniquement

            var dir = Path.Combine(Path.GetTempPath(), "optiscan_acl_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                DirectoryHardening.HardenDataDirectory(dir);

                // Le propriétaire courant garde un accès complet : lecture/écriture d'un fichier.
                var probe = Path.Combine(dir, "probe.txt");
                File.WriteAllText(probe, "ok");
                Assert.Equal("ok", File.ReadAllText(probe));

                // L'héritage est rompu (protection activée).
                var security = new DirectoryInfo(dir).GetAccessControl();
                Assert.True(security.AreAccessRulesProtected);
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Fact]
        public void HardenDataDirectory_OnMissingDirectory_DoesNotThrow()
        {
            var missing = Path.Combine(Path.GetTempPath(), "optiscan_missing_" + Guid.NewGuid().ToString("N"));
            // Ne doit jamais lever : best-effort silencieux.
            DirectoryHardening.HardenDataDirectory(missing);
        }
    }
}
