using System.Text.RegularExpressions;
using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Garde-fous de la restructuration des identifiants de protection :
/// pas de version produit dans les noms, et C# / C++ / Inno Setup synchronisés.
/// </summary>
public sealed class ProtectionIdentifiersTests
{
    private static readonly Regex VersionSuffix = new(@"[_\s]?[vV]\d+$", RegexOptions.CultureInvariant);

    [Fact]
    public void Identifiers_do_not_embed_a_product_version()
    {
        var identifiers = new[]
        {
            ProtectionIdentifiers.ServiceName,
            ProtectionIdentifiers.ServiceDescription,
            ProtectionIdentifiers.PipeName,
        };

        Assert.Equal("optiSCAN Protection v3", ProtectionIdentifiers.ServiceDisplayName);
        Assert.Equal("optiSCAN Protection v3", ProtectionIdentifiers.EventSourceName);

        foreach (var identifier in identifiers)
        {
            Assert.DoesNotMatch(VersionSuffix, identifier);
            Assert.DoesNotMatch(new Regex(@"\bv\d+(\.\d+)*\b", RegexOptions.IgnoreCase), identifier);
        }
    }

    [Fact]
    public void Legacy_event_sources_are_distinct_from_current_name()
    {
        Assert.DoesNotContain(ProtectionIdentifiers.EventSourceName, ProtectionIdentifiers.LegacyEventSourceNames);
        Assert.Contains("optiSCAN Protection v2", ProtectionIdentifiers.LegacyEventSourceNames);
        Assert.Equal("optiSCANProtection", ProtectionIdentifiers.ServiceName);
        Assert.Equal("optiSCAN_Protection", ProtectionIdentifiers.PipeName);
    }

    [Fact]
    public void App_bootstrap_and_pipe_contracts_use_the_single_source()
    {
        Assert.Equal(ProtectionIdentifiers.ServiceName, PlatformProtectionBootstrap.ServiceName);
        Assert.Equal(ProtectionIdentifiers.ServiceDisplayName, PlatformProtectionBootstrap.ServiceDisplayName);
        Assert.Equal(ProtectionIdentifiers.PipeName, ProtectionPipeNames.Protection);
    }

    [Fact]
    public void Native_amsi_header_mirrors_csharp_identifiers()
    {
        var header = ReadRepoFile("native", "optiSCAN.AmsiProvider", "protection_identifiers.h");
        if (header == null)
            return; // exécution hors dépôt (artefact de test isolé)

        Assert.Contains($"L\"\\\\\\\\.\\\\pipe\\\\{ProtectionIdentifiers.PipeName}\"", header);
        Assert.Matches(new Regex($@"kProtocolVersion\s*=\s*{ProtectionIdentifiers.ProtocolVersion}\s*;"), header);
        Assert.Contains($"kProtocolVersionJson[] = \"{ProtectionIdentifiers.ProtocolVersion}\"", header);
    }

    [Fact]
    public void Native_amsi_provider_has_no_hardcoded_pipe_name()
    {
        var source = ReadRepoFile("native", "optiSCAN.AmsiProvider", "amsi_provider.cpp");
        if (source == null)
            return;

        Assert.DoesNotContain("\\\\pipe\\\\", source);
        Assert.Contains("optiscan::ids::kProtectionPipePath", source);
    }

    [Fact]
    public void Installer_include_mirrors_csharp_identifiers()
    {
        var iss = ReadRepoFile("installer", "protection_identifiers.iss");
        if (iss == null)
            return;

        AssertIssDefine(iss, "ProtectionServiceName", ProtectionIdentifiers.ServiceName);
        AssertIssDefine(iss, "ProtectionServiceDisplayName", ProtectionIdentifiers.ServiceDisplayName);
        AssertIssDefine(iss, "ProtectionServiceDescription", ProtectionIdentifiers.ServiceDescription);
    }

    [Fact]
    public void Installer_script_has_no_hardcoded_service_name()
    {
        var setup = ReadRepoFile("installer", "setup.iss");
        if (setup == null)
            return;

        Assert.Contains("#include \"protection_identifiers.iss\"", setup);
        Assert.DoesNotContain("optiSCANProtectionV", setup);
        Assert.DoesNotContain("'stop optiSCANProtection", setup);
    }

    private static void AssertIssDefine(string iss, string name, string expected)
    {
        var match = Regex.Match(iss, $@"^#define\s+{name}\s+""([^""]*)""", RegexOptions.Multiline);
        Assert.True(match.Success, $"#define {name} absent de protection_identifiers.iss");
        Assert.Equal(expected, match.Groups[1].Value);
    }

    private static string? ReadRepoFile(params string[] parts)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && !string.IsNullOrEmpty(dir); i++)
        {
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln")))
            {
                var path = Path.Combine(new[] { dir }.Concat(parts).ToArray());
                return File.Exists(path) ? File.ReadAllText(path) : throw new FileNotFoundException(path);
            }

            dir = Path.GetDirectoryName(dir);
        }

        return null;
    }
}
