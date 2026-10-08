using System.Text.RegularExpressions;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Relecture du 7 octobre 2026 : outils Windows lancés par chemin complet, suppression des
/// partages qui rend compte de chaque échec, ressources et publication du service.
/// </summary>
public sealed class ReviewOctober7Tests
{
    // ── Outils système : jamais par nom nu ───────────────────────────────────────

    [Fact]
    public void SystemExecutables_are_rooted_in_the_system_directories()
    {
        if (!OperatingSystem.IsWindows())
            return; // Environment.SystemDirectory est vide hors Windows

        Assert.Equal(Path.Combine(Environment.SystemDirectory, "sc.exe"), SystemExecutables.System32("sc.exe"));
        Assert.True(Path.IsPathRooted(SystemExecutables.PowerShell));
        Assert.EndsWith(Path.Combine("WindowsPowerShell", "v1.0", "powershell.exe"), SystemExecutables.PowerShell);
        Assert.EndsWith("explorer.exe", SystemExecutables.Explorer);
    }

    [Fact]
    public void No_process_is_started_from_a_bare_executable_name()
    {
        var root = ResolveRepoRoot();
        if (root == null)
            return; // binaires copiés hors du dépôt : rien à relire

        // FileName = "sc.exe", new ProcessStartInfo("sc.exe"), RunProcess("sc.exe", …)
        var bare = new Regex(
            @"(FileName\s*=\s*|ProcessStartInfo\(\s*|Process\.Start\(\s*|RunProcess\(\s*)""[A-Za-z0-9_.-]+\.exe""",
            RegexOptions.CultureInvariant);

        var offenders = new[] { "optiSCAN", "optiSCAN.Service", "optiSCAN.Platform" }
            .Select(p => Path.Combine(root, p))
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.cs", SearchOption.AllDirectories))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                        && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, i, line)))
            .Where(x => bare.IsMatch(x.line))
            .Select(x => $"{Path.GetRelativePath(root, x.f)}:{x.i + 1}")
            .ToList();

        Assert.True(offenders.Count == 0, "Exécutables lancés par nom nu : " + string.Join(", ", offenders));
    }

    // ── Partages : chaque échec compte ───────────────────────────────────────────

    [Fact]
    public void RemoveShares_command_tries_every_share_and_reports_any_failure()
    {
        var net = @"C:\Windows\System32\net.exe";
        var cmd = SecurityPostureService.BuildRemoveSharesCommand(new[] { "Docs", "Media" }, net);

        Assert.StartsWith("/d /s /c \"", cmd);
        Assert.EndsWith("\"", cmd);
        Assert.Contains($"\"{net}\" share \"Docs\" /delete || set OPTISCAN_SHARE_FAIL=1", cmd);
        Assert.Contains($"\"{net}\" share \"Media\" /delete || set OPTISCAN_SHARE_FAIL=1", cmd);
        // la variable est vidée au début et testée à l'exécution, à la fin
        Assert.True(cmd.IndexOf("set \"OPTISCAN_SHARE_FAIL=\"", StringComparison.Ordinal)
                    < cmd.IndexOf("share \"Docs\"", StringComparison.Ordinal));
        Assert.EndsWith("if defined OPTISCAN_SHARE_FAIL exit 1\"", cmd);
        Assert.DoesNotContain("%", cmd);
    }

    // ── Publication : ressources et service ──────────────────────────────────────

    [Fact]
    public void Project_resources_match_file_names_exactly()
    {
        var root = ResolveRepoRoot();
        if (root == null)
            return;

        // Sous Windows la casse est ignorée ; sous Linux ou macOS un écart casse la compilation.
        var projectDir = Path.Combine(root, "optiSCAN");
        var csproj = File.ReadAllText(Path.Combine(projectDir, "optiSCAN.csproj"));
        var actual = Directory.EnumerateFiles(projectDir).Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);

        var missing = Regex.Matches(csproj, @"<Resource\s+Include=""([^""\\/*]+)""")
            .Select(m => m.Groups[1].Value)
            .Where(name => !actual.Contains(name))
            .ToList();

        Assert.True(missing.Count == 0, "Ressources dont la casse diffère du fichier : " + string.Join(", ", missing));
    }

    [Fact]
    public void Release_checks_require_the_service_assembly()
    {
        var root = ResolveRepoRoot();
        if (root == null)
            return;

        var verify = File.ReadAllText(Path.Combine(root, "scripts", "verify-runtime-deps.ps1"));
        Assert.Contains("Check \"optiSCAN.Service.exe\"", verify);
        Assert.Contains("Check \"optiSCAN.Service.dll\"", verify);

        var setup = File.ReadAllText(Path.Combine(root, "installer", "setup.iss"));
        Assert.Contains("#ifndef AllowMissingService", setup);
        Assert.DoesNotContain("optiSCAN.Service.exe\"; DestDir", setup); // jamais l'exe seul

        var prepare = File.ReadAllText(Path.Combine(root, "scripts", "prepare-release-v3.ps1"));
        Assert.DoesNotContain("--self-contained false", prepare);
        Assert.DoesNotContain("SilentlyContinue", prepare.Split("Invoke-Step 'dotnet publish'")[1].Split("Invoke-Step")[0]);
    }

    // ── Interface : la suite d'un gestionnaire reste sur le thread UI ────────────

    [Fact]
    public void Views_never_leave_the_UI_thread_after_an_await()
    {
        var root = ResolveRepoRoot();
        if (root == null)
            return;

        // Après ConfigureAwait(false), tout accès à un contrôle WPF lève une exception, et
        // CommandManager.InvalidateRequerySuggested hors du thread UI laisse les boutons grisés.
        var files = Directory.EnumerateFiles(Path.Combine(root, "optiSCAN", "Views"), "*.cs", SearchOption.AllDirectories)
            .Append(Path.Combine(root, "optiSCAN", "ViewModels", "RelayCommand.cs"));

        var offenders = files
            .Where(File.Exists)
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, i, line)))
            .Where(x => x.line.Contains("ConfigureAwait(false)", StringComparison.Ordinal)
                        && !x.line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            .Select(x => $"{Path.GetRelativePath(root, x.f)}:{x.i + 1}")
            .ToList();

        Assert.True(offenders.Count == 0, "ConfigureAwait(false) dans le code d'interface : " + string.Join(", ", offenders));
    }

    private static string? ResolveRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++)
        {
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln")))
                return dir;
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }
}
