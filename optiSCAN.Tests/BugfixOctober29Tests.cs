// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;
using optiSCAN.Services;
using System.Globalization;
using System.Text.Json;

namespace optiSCAN.Tests;

/// <summary>Non-régression des corrections du 29 octobre 2026.</summary>
public sealed class BugfixOctober29Tests
{
    // ── Quarantaine : signature du manifeste indépendante de la langue ─────────

    [Fact]
    public void Quarantine_entry_serialization_has_no_culture_dependent_fields()
    {
        var entry = new QuarantineEntry { Id = "a", OriginalPath = @"C:\x\virus.exe", OriginalSize = 1536 };
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            var fr = JsonSerializer.Serialize(entry);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
            var en = JsonSerializer.Serialize(entry);

            Assert.Equal(fr, en);
            Assert.DoesNotContain("SizeDisplay", fr, StringComparison.Ordinal);
            Assert.DoesNotContain("FileName", fr, StringComparison.Ordinal);
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    [Fact]
    public void Legacy_canonical_json_reproduces_the_former_serialization()
    {
        var entries = new List<QuarantineEntry>
        {
            new() { Id = "b", OriginalPath = @"C:\Users\é\Téléchargements\x&y.exe", OriginalSize = 1536, Sha256 = "AB", SourceSessionId = Guid.Empty },
            new() { Id = "a", OriginalPath = @"C:\a.bin", OriginalSize = -1 },
        };

        var fr = QuarantineManager.LegacyCanonicalJson(entries, CultureInfo.GetCultureInfo("fr-FR"));
        var en = QuarantineManager.LegacyCanonicalJson(entries, CultureInfo.GetCultureInfo("en-US"));

        Assert.Contains("\"SizeDisplay\":\"1,5 Ko\"", fr, StringComparison.Ordinal);
        Assert.Contains("\"SizeDisplay\":\"1.5 Ko\"", en, StringComparison.Ordinal);
        Assert.Contains("\"SizeDisplay\":\"Inconnu\"", fr, StringComparison.Ordinal);
        // Ordre par Id, champs d'affichage en dernier comme dans l'ancienne classe.
        Assert.StartsWith("[{\"Id\":\"a\"", fr, StringComparison.Ordinal);
        Assert.EndsWith("\"SizeDisplay\":\"1,5 Ko\"}]", fr, StringComparison.Ordinal);
    }

    // ── ClamAV : un fichier exclu ne fait plus passer l'analyse en erreur ──────

    [Fact]
    public void Excluded_detection_is_counted_and_keeps_scan_completed()
    {
        var exclusions = new FixedExclusions();
        exclusions.Current.ExcludedFilePaths = new List<string> { @"C:\temp\faux-positif.exe" };
        var result = new ScanResult();

        ClamScanLineParser.ProcessLine(@"C:\temp\faux-positif.exe: Win.Test.FP FOUND", result, null, exclusions);

        Assert.Empty(result.Threats);
        Assert.Equal(1, result.SuppressedDetections);
        // clamscan rend 1 : la détection écartée compte comme lue.
        var status = ClamAvEngine.ClassifyExit(1, result.Threats.Count + result.SuppressedDetections, cancelled: false, out var error);
        Assert.Equal(ScanStatus.Completed, status);
        Assert.Null(error);
    }

    [Fact]
    public void Suppressed_detections_are_not_persisted_in_history()
    {
        var json = JsonSerializer.Serialize(new ScanResult { SuppressedDetections = 3 });
        Assert.DoesNotContain(nameof(ScanResult.SuppressedDetections), json, StringComparison.Ordinal);
    }

    // ── Démarrage : la fenêtre principale n'est chargée qu'en mode interface ───

    [Fact]
    public void Main_window_is_created_only_on_the_interactive_path()
    {
        var xaml = File.ReadAllText(Path.Combine(RepoRoot(), "optiSCAN", "App.xaml"));
        var app = File.ReadAllText(Path.Combine(RepoRoot(), "optiSCAN", "App.xaml.cs"));
        var code = string.Join('\n', app.Split('\n').Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal)));

        // Pas de chargement automatique, et jamais StartupUri = null (ArgumentNullException en .NET 10).
        Assert.DoesNotContain("StartupUri", xaml, StringComparison.Ordinal);
        Assert.DoesNotContain("StartupUri", code, StringComparison.Ordinal);

        var singleInstance = code.IndexOf("new Mutex(true, MutexName, out createdNew)", StringComparison.Ordinal);
        var created = code.IndexOf("new MainWindow()", StringComparison.Ordinal);
        Assert.True(singleInstance >= 0 && created > singleInstance, "MainWindow n'est créée qu'après le contrôle d'instance unique.");
        Assert.Equal(created, code.LastIndexOf("new MainWindow()", StringComparison.Ordinal));
        Assert.Contains("ServiceContainer.IsCreated", code, StringComparison.Ordinal);
    }

    // ── Installeur : mise à jour avec un service déjà enregistré ──────────────

    [Fact]
    public void Installer_reconfigures_an_existing_service_instead_of_failing()
    {
        var setup = File.ReadAllText(Path.Combine(RepoRoot(), "installer", "setup.iss"));
        Assert.Contains("if ResultCode = 1073 then", setup, StringComparison.Ordinal);
        Assert.Contains("'config {#ProtectionServiceName} '", setup, StringComparison.Ordinal);
        Assert.Contains("/F /IM optiSCAN.Host.exe /T", setup, StringComparison.Ordinal);
    }

    // ── YARA-Forge : la release épinglée est interrogée, pas « latest » ───────

    [Fact]
    public void Rules_update_queries_the_pinned_release_not_latest()
    {
        Assert.Equal(
            "https://api.github.com/repos/YARAHQ/yara-forge/releases/tags/" + YaraForgePackageIntegrity.TrustedTag,
            YaraForgePackageIntegrity.TrustedReleaseApiUrl);
        var updater = File.ReadAllText(Path.Combine(RepoRoot(), "optiSCAN.Engine", "Services", "YaraForgeUpdater.cs"));
        Assert.DoesNotContain("releases/latest", updater, StringComparison.Ordinal);
        Assert.Contains("YaraForgePackageIntegrity.TrustedReleaseApiUrl", updater, StringComparison.Ordinal);
    }

    private sealed class FixedExclusions : IExclusionSettingsAccessor
    {
        public ExclusionSettings Current { get; } = new();
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "optiSCAN.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("optiSCAN.sln introuvable");
    }
}
