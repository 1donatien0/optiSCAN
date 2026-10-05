using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using optiSCAN.Models;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Audit 360 du 2 octobre 2026, constats E, M, F et X : un test par correction, et les composants qui
/// n'avaient aucun test (AtomicFile, ElevationHelper, ProtectionPipeAcl, ThreatRepairService,
/// ProcessStartMonitor).
/// </summary>
public sealed class AuditFollowUpTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "optiscan_ca_" + Guid.NewGuid().ToString("N"));

    public AuditFollowUpTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    // ── E3 : MpCmdRun ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(@"C:\Users\a\Downloads\setup.exe", true)]
    [InlineData(@"C:\Users\a\x"" -Restore -Name x.exe", false)]
    [InlineData("-Restore", false)]
    [InlineData(@"relative\file.exe", false)]
    [InlineData("C:\\a\nb.exe", false)]
    [InlineData("", false)]
    public void ThreatRepair_accepts_only_plain_absolute_paths(string path, bool expected)
    {
        if (!OperatingSystem.IsWindows())
            return; // Path.IsPathFullyQualified dépend de la plateforme
        Assert.Equal(expected, ThreatRepairService.IsSafeScanTarget(path));
    }

    [Fact]
    public void ThreatRepair_passes_the_path_as_a_single_argument()
    {
        var args = ThreatRepairService.BuildDefenderScanArguments(@"C:\dossier avec espaces\f.exe");
        Assert.Equal(new[] { "-Scan", "-ScanType", "3", "-File", @"C:\dossier avec espaces\f.exe", "-DisableRemediation" }, args);
    }

    // ── AtomicFile (aucun test auparavant) ───────────────────────────────────────

    [Fact]
    public void AtomicFile_keeps_previous_version_as_backup_and_reads_it_back()
    {
        var path = Path.Combine(_root, "state.json");
        AtomicFile.WriteAllText(path, "v1");
        AtomicFile.WriteAllText(path, "v2");

        Assert.Equal("v2", File.ReadAllText(path));
        Assert.Equal("v1", File.ReadAllText(path + ".bak"));

        File.WriteAllText(path, "corrompu");
        var read = AtomicFile.ReadWithBackup(path, s => s == "corrompu" ? throw new InvalidDataException() : s, "défaut");
        Assert.Equal("v1", read);
    }

    [Fact]
    public void AtomicFile_concurrent_writes_leave_one_complete_version_and_no_temp_file()
    {
        var path = Path.Combine(_root, "concurrent.txt");
        var payloads = Enumerable.Range(0, 8).Select(i => new string((char)('a' + i), 4096)).ToArray();

        Parallel.ForEach(payloads, p =>
        {
            try { AtomicFile.WriteAllText(path, p); }
            catch (IOException) { /* une écriture concurrente peut perdre la course au renommage */ }
            catch (UnauthorizedAccessException) { /* idem sous Windows */ }
        });

        Assert.Contains(File.ReadAllText(path), payloads);
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public void AtomicFile_reads_fallback_when_nothing_exists() =>
        Assert.Equal("défaut", AtomicFile.ReadWithBackup(Path.Combine(_root, "absent"), s => s, "défaut"));

    // ── ElevationHelper (aucun test auparavant) ──────────────────────────────────

    [Fact]
    public void NeedsElevation_respects_folder_boundaries()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.True(ElevationHelper.NeedsElevation(Path.Combine(windows, "System32", "drivers", "etc", "hosts")));
        Assert.False(ElevationHelper.NeedsElevation(windows + "Apps\\tool.exe"));
        Assert.False(ElevationHelper.NeedsElevation(Path.Combine(Path.GetTempPath(), "x.exe")));
        Assert.False(ElevationHelper.NeedsElevation(string.Empty));
    }

    // ── ProtectionPipeAcl (aucun test auparavant) ────────────────────────────────

    [Fact]
    public void PipeAcl_lets_authenticated_users_connect_but_not_create_instances_or_change_the_acl()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var security = ProtectionPipeAcl.BuildPipeSecurity();
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
        var authenticated = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var anonymous = new SecurityIdentifier(WellKnownSidType.AnonymousSid, null);

        Assert.All(rules, r => Assert.Equal(AccessControlType.Allow, r.AccessControlType));
        Assert.DoesNotContain(rules, r => everyone.Equals(r.IdentityReference) || anonymous.Equals(r.IdentityReference));

        var users = Assert.Single(rules, r => authenticated.Equals(r.IdentityReference));
        Assert.Equal(0, (int)(users.PipeAccessRights & PipeAccessRights.CreateNewInstance));
        Assert.Equal(0, (int)(users.PipeAccessRights & PipeAccessRights.ChangePermissions));
        Assert.Equal(0, (int)(users.PipeAccessRights & PipeAccessRights.TakeOwnership));
        Assert.NotEqual(0, (int)(users.PipeAccessRights & PipeAccessRights.ReadWrite));

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        Assert.Contains(rules, r => system.Equals(r.IdentityReference) && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));
    }

    // ── ProcessStartMonitor (aucun test dédié auparavant) ────────────────────────

    [Fact]
    public void ProcessStartMonitor_extracts_quoted_and_plain_script_paths()
    {
        var candidates = ProcessStartMonitor.ExtractCommandLineCandidates(
            "wscript.exe //B \"C:\\Users\\a\\My Docs\\run.vbs\" C:\\Temp\\other.js");

        Assert.Contains(@"C:\Users\a\My Docs\run.vbs", candidates);
        Assert.Contains(@"C:\Temp\other.js", candidates);
        Assert.Equal(candidates.Count, candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void ProcessStartMonitor_prunes_expired_dedup_entries()
    {
        var monitor = new ProcessStartMonitor(
            new ScanOrchestrator(new NoClam(), new NoYara()),
            new QuarantineManager(Path.Combine(_root, "q")),
            new NotificationService());
        var now = DateTime.UtcNow;
        for (var i = 0; i < ProcessStartMonitor.RecentScansPruneThreshold; i++)
            monitor.RecordRecentScanForTest($@"C:\old\{i}.exe", now.AddMinutes(-5));
        monitor.RecordRecentScanForTest(@"C:\recent.exe", now);

        monitor.PruneRecentScans(now);

        Assert.Equal(1, monitor.RecentScansCount);
    }

    [Fact]
    public void ProcessStartMonitor_caps_the_cache_even_when_every_entry_is_recent()
    {
        var monitor = new ProcessStartMonitor(
            new ScanOrchestrator(new NoClam(), new NoYara()),
            new QuarantineManager(Path.Combine(_root, "q")),
            new NotificationService());
        var now = DateTime.UtcNow;
        for (var i = 0; i < ProcessStartMonitor.MaxRecentScans + 500; i++)
            monitor.RecordRecentScanForTest($@"C:\burst\{i}.exe", now.AddMilliseconds(i));

        monitor.PruneRecentScans(now);

        Assert.True(monitor.RecentScansCount <= ProcessStartMonitor.MaxRecentScans);
    }

    [Fact]
    public void ProcessStartMonitor_dispose_is_idempotent_without_pending_work()
    {
        var monitor = new ProcessStartMonitor(
            new ScanOrchestrator(new NoClam(), new NoYara()),
            new QuarantineManager(Path.Combine(_root, "q")),
            new NotificationService());
        monitor.Dispose();
        monitor.Dispose();
        Assert.Equal(0, monitor.InflightCount);
    }

    // ── M12 : listes de menaces publiées jamais modifiées sur place ──────────────

    [Fact]
    public void History_threat_lists_seen_by_readers_are_never_mutated()
    {
        var logger = new ScanLogManager(Path.Combine(_root, "logs"));
        var sessionId = Guid.NewGuid();
        logger.SaveScanResult(new ScanResult
        {
            SessionId = sessionId,
            StartedAt = DateTime.Now,
            Type = ScanType.File,
            TargetPath = @"C:\a",
            Status = ScanStatus.Completed,
            Threats = { ThreatInfo.FromClamAv(@"C:\a\x.exe", "T1", 1), ThreatInfo.FromClamAv(@"C:\a\y.exe", "T2", 1) },
        });

        var seenByReader = logger.GetHistory().Single().Threats;
        Assert.True(logger.TryRemoveThreatFromSession(sessionId, @"C:\a\x.exe"));

        Assert.Equal(2, seenByReader.Count);
        Assert.Single(logger.GetHistory().Single().Threats);
    }

    // ── F4 : la migration ne supprime le clair que si la copie sécurisée est relue ─

    [Fact]
    public void SecureStore_migration_keeps_plaintext_when_the_secure_write_fails()
    {
        if (!OperatingSystem.IsWindows())
            return; // DPAPI
        var plain = Path.Combine(_root, "prefs.json");
        File.WriteAllText(plain, "{\"Name\":\"valeur\"}");
        var blocker = Path.Combine(_root, "blocker");
        File.WriteAllText(blocker, "un fichier, pas un dossier");

        var migrated = SecureStore.MigrateFromPlaintext<MigrationSample>(plain, Path.Combine(blocker, "prefs.dat"));

        Assert.Equal("valeur", migrated?.Name);
        Assert.True(File.Exists(plain));
    }

    public sealed class MigrationSample
    {
        public string Name { get; set; } = string.Empty;
    }

    // ── E5 : RTP analyse la copie, les menaces gardent le chemin d'origine ───────

    [Fact]
    public void RealTimeProtection_rebinds_staged_paths_to_the_original()
    {
        var result = new ScanResult { TargetPath = @"C:\staging\abc\f.zip" };
        result.Threats.Add(new ThreatInfo { FilePath = @"C:\staging\abc\f.zip", VirusName = "A" });
        result.Threats.Add(new ThreatInfo { FilePath = @"C:\staging\abc\f.zip!inner.exe", VirusName = "B" });

        RealTimeProtection.RebindStagedResult(result, @"C:\staging\abc\f.zip", @"C:\Users\a\Downloads\f.zip");

        Assert.Equal(@"C:\Users\a\Downloads\f.zip", result.TargetPath);
        Assert.Equal(@"C:\Users\a\Downloads\f.zip", result.Threats[0].FilePath);
        Assert.Equal(@"C:\Users\a\Downloads\f.zip!inner.exe", result.Threats[1].FilePath);
    }

    // ── E10 : un YARA incomplet n'est jamais « propre » ─────────────────────────

    [Fact]
    public async Task Orchestrator_marks_incomplete_yara_as_error_but_keeps_partial_matches()
    {
        var file = Path.Combine(_root, "sample.bin");
        await File.WriteAllBytesAsync(file, new byte[] { 1, 2, 3 });
        var orchestrator = new ScanOrchestrator(new NoClam(), new IncompleteYara());

        var result = await orchestrator.ScanFileAsync(file);

        Assert.NotEqual(ScanStatus.Completed, result.Status);
        Assert.Contains(result.Threats, t => t.VirusName == "Partial_Rule");
    }

    // ── E8 : ancre de confiance ClamAV épinglée ──────────────────────────────────

    [Fact]
    public void ClamAv_root_certificate_pin_matches_the_bundled_certificate_only()
    {
        var bundled = FindRepoFile("optiSCAN", "clamav", "certs", "clamav.crt");
        if (bundled != null)
            Assert.True(FreshclamUpdater.IsPinnedRootCert(bundled));
        Assert.False(FreshclamUpdater.IsPinnedRootCert(new byte[300]));
    }

    // ── M3 : freshclam.conf ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("C:/ProgramData/optiSCAN/db", true)]
    [InlineData("C:/x\"\nPrivateMirror evil.example", false)]
    [InlineData("C:/x\r\nDatabaseMirror evil", false)]
    [InlineData("", false)]
    public void FreshclamConf_refuses_values_that_break_out_of_quotes(string value, bool expected) =>
        Assert.Equal(expected, FreshclamConfSupport.IsSafeConfValue(value));

    [Fact]
    public void FreshclamConf_build_returns_null_for_an_injected_path() =>
        Assert.Null(FreshclamConfSupport.BuildConfBytes(3, "C:/db\"\nPrivateMirror x", "C:/log.txt"));

    // ── M4 : nom de conteneur clamd non devinable ────────────────────────────────

    [Fact]
    public void ClamdContainerName_requires_a_random_suffix()
    {
        Assert.False(ClamdContainerName.IsValid(ClamdContainerName.LegacyName));
        Assert.False(ClamdContainerName.IsValid("optiSCAN.clamd.1234"));
        Assert.True(ClamdContainerName.IsValid("optiSCAN.clamd." + new string('A', 32)));
    }

    // ── M5 : exclusions de dossiers système refusées ─────────────────────────────

    [Fact]
    public void Exclusions_refuse_drive_roots_and_system_folders()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        Assert.True(ExclusionSettings.IsForbiddenFolderExclusion(Path.GetPathRoot(windows)));
        Assert.True(ExclusionSettings.IsForbiddenFolderExclusion(windows));
        Assert.True(ExclusionSettings.IsForbiddenFolderExclusion(Path.Combine(windows, "Temp")));
        Assert.True(ExclusionSettings.IsForbiddenFolderExclusion(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        Assert.True(ExclusionSettings.IsForbiddenFolderExclusion(profile));
        Assert.False(ExclusionSettings.IsForbiddenFolderExclusion(Path.Combine(profile, "Projets", "build")));

        var settings = new ExclusionSettings { ExcludedFolders = { Path.GetPathRoot(windows)! } };
        Assert.False(settings.IsFolderExcluded(Path.Combine(profile, "Downloads", "x.exe")));
    }

    // ── M10 : relais de progression partagé entre deux moteurs ───────────────────

    [Fact]
    public void ProgressRelay_stays_monotonic_under_concurrent_reports()
    {
        var relay = new ScanProgressRelay();
        Parallel.For(1, 2001, i =>
        {
            relay.Normalize(new ScanProgress { ClamFilesScanned = i, Phase = ScanPhase.Scanning });
            relay.Normalize(new ScanProgress { YaraFilesScanned = i, Phase = ScanPhase.Scanning });
        });
        Assert.True(relay.FilesScannedHigh >= 2000);
    }

    // ── M16 : niveau de risque indépendant de l'ordre des mots-clés ─────────────

    [Fact]
    public void RiskScoring_takes_the_highest_matching_keyword()
    {
        var worm = RiskScoringService.Assess(new ThreatInfo { FilePath = @"C:\a\f.txt", VirusName = "Worm.Win32.Agent", DetectedBy = "ClamAV" });
        var unknownClam = RiskScoringService.GetSeverityLevel(new ThreatInfo { VirusName = "Win.Xyz.Foo-123", DetectedBy = "ClamAV" });
        var unknownYara = RiskScoringService.GetSeverityLevel(new ThreatInfo { VirusName = "SUSP_Foo", DetectedBy = "YARA" });

        Assert.Contains(worm.Reasons, r => r.Contains("worm.win32", StringComparison.OrdinalIgnoreCase));
        Assert.NotEqual(unknownClam, unknownYara);
    }

    // ── X1 : noms de partage passés à cmd.exe ────────────────────────────────────

    [Theory]
    [InlineData("Documents", true)]
    [InlineData("x\" & calc & \"", false)]
    [InlineData("a|b", false)]
    [InlineData("100%", false)]
    public void ShareNames_with_cmd_metacharacters_are_refused(string name, bool expected) =>
        Assert.Equal(expected, SecurityPostureService.IsCmdSafeShareName(name));

    // ── X3 : dossier d'installation réservé aux administrateurs ──────────────────

    // Propriétés (et non champs statiques) : hors Windows, SecurityIdentifier lève une exception
    // qui ferait échouer l'initialisation de toute la classe de tests.
    private static SecurityIdentifier SystemSid => new(WellKnownSidType.LocalSystemSid, null);
    private static SecurityIdentifier AdminsSid => new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static SecurityIdentifier UsersSid => new(WellKnownSidType.BuiltinUsersSid, null);
    private static SecurityIdentifier AuthenticatedUsersSid => new(WellKnownSidType.AuthenticatedUserSid, null);
    private static SecurityIdentifier CreatorOwnerSid => new(WellKnownSidType.CreatorOwnerSid, null);

    private static DirectorySecurity AdminOnlyDirectory(SecurityIdentifier? owner = null)
    {
        var security = new DirectorySecurity();
        security.SetOwner(owner ?? AdminsSid);
        security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(UsersSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        return security;
    }

    [Fact]
    public void InstallTrust_accepts_a_folder_users_can_only_read()
    {
        if (!OperatingSystem.IsWindows())
            return; // API ACL Windows
        Assert.True(InstallLocationTrust.IsAdminOnlySecurity(AdminOnlyDirectory(), InstallLocationTrust.ContentWriteRights, out _));
    }

    [Fact]
    public void InstallTrust_refuses_a_folder_inheriting_modify_for_authenticated_users()
    {
        if (!OperatingSystem.IsWindows())
            return; // API ACL Windows
        // Cas d'un dossier créé à la racine d'un volume (C:\optiSCAN, D:\Apps\optiSCAN).
        var security = AdminOnlyDirectory();
        security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsersSid, FileSystemRights.Modify, AccessControlType.Allow));

        Assert.False(InstallLocationTrust.IsAdminOnlySecurity(security, InstallLocationTrust.ContentWriteRights, out var reason));
        Assert.Contains(AuthenticatedUsersSid.Value, reason);
    }

    [Fact]
    public void InstallTrust_refuses_a_folder_owned_by_a_user()
    {
        if (!OperatingSystem.IsWindows())
            return; // API ACL Windows
        var user = new SecurityIdentifier("S-1-5-21-1000000000-2000000000-3000000000-1001");
        Assert.False(InstallLocationTrust.IsAdminOnlySecurity(AdminOnlyDirectory(user), InstallLocationTrust.ContentWriteRights, out _));
    }

    [Fact]
    public void InstallTrust_ignores_inherit_only_templates_and_folder_creation_on_parents()
    {
        if (!OperatingSystem.IsWindows())
            return; // API ACL Windows
        // Racine d'un volume : les utilisateurs peuvent y créer un dossier (AppendData) et
        // reçoivent un modèle CREATOR OWNER, sans pouvoir renommer un dossier existant.
        var root = AdminOnlyDirectory(SystemSid);
        root.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsersSid, FileSystemRights.AppendData, AccessControlType.Allow));
        root.AddAccessRule(new FileSystemAccessRule(
            CreatorOwnerSid, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly,
            AccessControlType.Allow));

        Assert.True(InstallLocationTrust.IsAdminOnlySecurity(root, InstallLocationTrust.AncestorWriteRights, out _));

        root.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsersSid, FileSystemRights.Delete, AccessControlType.Allow));
        Assert.False(InstallLocationTrust.IsAdminOnlySecurity(root, InstallLocationTrust.AncestorWriteRights, out _));
    }

    [Fact]
    public void InstallTrust_refuses_a_user_writable_folder()
    {
        // Le dossier temporaire de l'utilisateur lui appartient ; hors Windows, le contrôle est refusé.
        Assert.False(InstallLocationTrust.IsAdminOnlyInstall(_root, out var reason));
        Assert.False(string.IsNullOrEmpty(reason));
    }

    [Fact]
    public void Defender_exclusions_never_target_a_user_writable_folder()
    {
        Assert.All(WindowsDefenderExclusionService.CollectExclusionPaths(), path =>
            Assert.True(InstallLocationTrust.IsAdminOnlyInstall(path, out _), path));
        if (!InstallLocationTrust.IsCurrentInstallTrusted(out _))
            Assert.Empty(WindowsDefenderExclusionService.CollectProcessExclusionPaths());
    }

    [Fact]
    public void Untrusted_install_keeps_only_engines_and_rules_out_of_scans()
    {
        var install = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (InstallLocationTrust.IsAdminOnlyInstall(install, out _))
            return; // installation réelle sous Program Files : exclue entière

        Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(install, "dropped.exe")));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(install, "rules", "test.yar")));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(install, "clamav", "database", "main.cvd")));
    }

    // ── X6 : copies d'analyse ignorées par le temps réel ─────────────────────────

    [Fact]
    public void Staging_folder_is_not_a_blind_spot_for_files_optiSCAN_did_not_stage()
    {
        var planted = Path.Combine(ScanStaging.Root, Guid.NewGuid().ToString("N"), "payload.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(planted)!);
        try
        {
            File.WriteAllText(planted, "x");
            Assert.False(ScanStaging.IsStagingPath(planted));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(planted)!, recursive: true);
        }
    }

    [Fact]
    public void Late_event_for_a_disposed_copy_is_ignored_but_a_recreated_file_is_scanned()
    {
        string stagedPath;
        using (var source = new MemoryStream("x"u8.ToArray()))
        using (var staged = ScanStaging.Stage(source, "late.bin"))
            stagedPath = staged.Path;

        Assert.True(ScanStaging.IsStagingPath(stagedPath));

        Directory.CreateDirectory(Path.GetDirectoryName(stagedPath)!);
        try
        {
            File.WriteAllText(stagedPath, "recréé");
            Assert.False(ScanStaging.IsStagingPath(stagedPath));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(stagedPath)!, recursive: true);
        }
    }

    // ── X7 : %LOCALAPPDATA%\optiSCAN analysé, sauf bases, règles et quarantaine ──

    [Fact]
    public void LocalAppData_optiSCAN_is_scanned_except_protected_subfolders()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();

        Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "payload.exe")));
        Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "Updates", "optiSCAN.exe")));
        Assert.False(OptiscanProtectedPaths.IsMandatoryExcludedFolder(root));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "clamav", "database", "daily.cvd")));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "rules", "core.yar")));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "Quarantine", "x.quar")));
    }

    [Fact]
    public void Former_whole_LocalAppData_exclusion_is_dropped_and_refused()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();
        var settings = new ExclusionSettings();
        settings.ExcludedFolders.Add(root);

        settings.EnsureProtectedFoldersListed();

        Assert.DoesNotContain(settings.ExcludedFolders,
            f => string.Equals(f.TrimEnd('\\', '/'), root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase));
        if (OperatingSystem.IsWindows())
            Assert.True(ExclusionSettings.IsForbiddenFolderExclusion(root)); // chemins Windows
        Assert.False(settings.IsFileExcluded(Path.Combine(root, "payload.exe")));
    }

    // ── X8 : serveur du pipe = processus du service ──────────────────────────────

    [Fact]
    public void PipeServerTrust_refuses_a_process_that_is_not_the_protection_service()
    {
        if (!OperatingSystem.IsWindows())
            return; // gestionnaire de services et instantané des processus Windows
        Assert.False(PipeServerTrust.IsProtectionServiceProcess(uint.MaxValue));
    }

    // ── F10 : sortie clamscan inattendue ─────────────────────────────────────────

    [Fact]
    public void ClamScanParser_ignores_an_out_of_range_file_count()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine("Scanned files: 99999999999999999999", result, null);
        Assert.Equal(0, result.FilesScanned);
    }

    private static string? FindRepoFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(new[] { dir.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    private sealed class NoClam : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => false;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, TargetPath = filePath, FilesScanned = 1 });
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, TargetPath = folderPath });
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, TargetPath = targetPath, FilesScanned = files.Count });
    }

    private sealed class NoYara : IYaraOrchestratorBackend
    {
        public bool IsAvailable => false;
        public int RulesCount => 0;
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) => Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) => Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) => Task.FromResult(new List<YaraMatch>());
    }

    /// <summary>YARA qui a lu une correspondance puis s'est arrêté (sortie tronquée, délai...).</summary>
    private sealed class IncompleteYara : IYaraOrchestratorBackend
    {
        public bool IsAvailable => true;
        public int RulesCount => 1;
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
            throw new YaraScanIncompleteException("Sortie YARA tronquée", new List<YaraMatch> { new() { RuleName = "Partial_Rule", FilePath = filePath } });
        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) => Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) => Task.FromResult(new List<YaraMatch>());
    }
}
