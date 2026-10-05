using System.Security.AccessControl;
using System.Security.Principal;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>Suite du durcissement : scan IPC sur copie, places du pipe par compte, politique, ProgramData.</summary>
public sealed class HardeningFollowUpTests
{
    [Fact]
    public void Staged_copy_is_independent_from_the_source_path_and_removed_afterwards()
    {
        var content = "contenu lu par le client"u8.ToArray();
        string stagedPath;
        using (var source = new MemoryStream(content))
        using (var staged = ScanStaging.Stage(source, "rapport.docm"))
        {
            stagedPath = staged.Path;
            Assert.Equal("rapport.docm", Path.GetFileName(stagedPath));
            Assert.Equal(content, File.ReadAllBytes(stagedPath));
            Assert.True(ScanStaging.IsStagingPath(stagedPath));
        }

        Assert.False(File.Exists(stagedPath));
        Assert.False(Directory.Exists(Path.GetDirectoryName(stagedPath)));
    }

    [Fact]
    public void Staging_refuses_content_that_grows_after_its_pinned_length_and_leaves_nothing_behind()
    {
        var before = Directory.Exists(ScanStaging.Root) ? Directory.GetDirectories(ScanStaging.Root).Length : 0;
        using var source = new MemoryStream("long"u8.ToArray());

        Assert.Throws<IOException>(() => ScanStaging.Stage(source, "big.bin", expectedLength: 3));

        var after = Directory.Exists(ScanStaging.Root) ? Directory.GetDirectories(ScanStaging.Root).Length : 0;
        Assert.Equal(before, after);
    }

    [Fact]
    public void Real_time_protection_ignores_only_staging_copies()
    {
        Assert.False(ScanStaging.IsStagingPath(Path.Combine(Path.GetTempPath(), "autre", "x.exe")));
        Assert.False(ScanStaging.IsStagingPath(null));
    }

    [Fact]
    public void One_account_cannot_take_more_than_its_pipe_slots()
    {
        var server = new ProtectionPipeServer(new ScanOrchestrator((ClamAvEngine?)null, (YaraEngine?)null), "optiSCAN_Test_" + Guid.NewGuid().ToString("N"));
        const string user = "S-1-5-21-1-2-3-1001";
        const string other = "S-1-5-21-1-2-3-1002";

        for (var i = 0; i < ProtectionPipeServer.MaxConcurrentPerAccount; i++)
            Assert.True(server.TryReserveClientSlot(user));
        Assert.False(server.TryReserveClientSlot(user));
        Assert.True(server.TryReserveClientSlot(other));

        server.ReleaseClientSlot(user);
        Assert.True(server.TryReserveClientSlot(user));

        for (var i = 0; i < 10; i++)
            Assert.True(server.TryReserveClientSlot(NamedPipeClientAccess.SystemAccount));
    }

    [Theory]
    [InlineData(true, true, false, true, true, true)]    // tout activer : renforcement
    [InlineData(false, false, false, true, false, false)] // couper le temps réel : admin requis
    [InlineData(true, false, true, true, false, false)]   // quarantaine auto : admin requis
    [InlineData(true, false, false, false, false, false)] // couper les mises à jour : admin requis
    public void Standard_accounts_may_only_strengthen_the_service_policy(
        bool realtime, bool monitor, bool quarantine, bool signatures, bool removable, bool allowed)
    {
        var path = Path.Combine(Path.GetTempPath(), "optiscan_policy_" + Guid.NewGuid().ToString("N") + ".json");
        HostPolicyStore.FilePathOverride = path; // absent : politique par défaut (temps réel et MAJ actifs)
        try
        {
            var request = new ProtectionPipeRequest
            {
                Operation = ProtectionPipeOperations.SetPolicy,
                RealTimeEnabled = realtime,
                ProcessMonitorEnabled = monitor,
                AutoQuarantineEnabled = quarantine,
                SignatureAutoUpdateEnabled = signatures,
                RemovableDriveScanEnabled = removable,
            };

            Assert.Equal(allowed, HostPolicyStore.IsStrengtheningOnly(request));
        }
        finally
        {
            HostPolicyStore.FilePathOverride = null;
        }
    }

    [Fact]
    public void Elevated_push_argument_round_trips()
    {
        var request = new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.SetPolicy,
            RealTimeEnabled = false,
            ProcessMonitorEnabled = true,
            AutoQuarantineEnabled = false,
            SignatureAutoUpdateEnabled = true,
            RemovableDriveScanEnabled = false,
        };

        var text = HostPolicyStore.ToArgument(request);
        Assert.True(HostPolicyStore.TryParseArgument(text, out var parsed));
        Assert.Equal(request.RealTimeEnabled, parsed.RealTimeEnabled);
        Assert.Equal(request.ProcessMonitorEnabled, parsed.ProcessMonitorEnabled);
        Assert.Equal(request.AutoQuarantineEnabled, parsed.AutoQuarantineEnabled);
        Assert.Equal(request.SignatureAutoUpdateEnabled, parsed.SignatureAutoUpdateEnabled);
        Assert.Equal(request.RemovableDriveScanEnabled, parsed.RemovableDriveScanEnabled);

        Assert.False(HostPolicyStore.TryParseArgument("rt=1,monitor=2", out _));
        Assert.False(HostPolicyStore.TryParseArgument("rt=1", out _));
        Assert.Equal(
            HeadlessScanArguments.Mode.PushHostPolicy,
            HeadlessScanArguments.ParseMode(new[] { "--push-host-policy", text, "--quiet" }));
        Assert.Equal(text, HeadlessScanArguments.GetPushHostPolicyArgument(new[] { "--push-host-policy", text }));
    }

    [Fact]
    public void ProgramData_entries_owned_by_admins_but_open_to_users_are_not_trusted()
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

        var clean = new FileSecurity();
        clean.SetOwner(admins);
        clean.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        clean.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        Assert.True(OptiScanProgramData.IsTrustedSecurity(clean));

        var openToUsers = new FileSecurity();
        openToUsers.SetOwner(admins);
        openToUsers.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        openToUsers.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Modify, AccessControlType.Allow));
        Assert.False(OptiScanProgramData.IsTrustedSecurity(openToUsers));

        var container = new FileSecurity();
        container.SetOwner(system);
        container.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier("S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069167804-1277922394"),
            FileSystemRights.ReadAndExecute,
            AccessControlType.Allow));
        Assert.True(OptiScanProgramData.IsTrustedSecurity(container));

        var userOwned = new FileSecurity();
        userOwned.SetOwner(users);
        Assert.False(OptiScanProgramData.IsTrustedSecurity(userOwned));
    }

    private sealed class ZeroStream : Stream
    {
        private readonly long _length;
        private long _position;

        public ZeroStream(long length) => _length = length;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = (int)Math.Min(count, _length - _position);
            Array.Clear(buffer, offset, n);
            _position += n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
