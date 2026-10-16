// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Tests;

/// <summary>Une seule chaîne de signature : SignPath Foundation, dans release.yml.</summary>
public sealed class SigningChainTests
{
    private static string? Root()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln")))
                return dir;
        return null;
    }

    [Fact]
    public void Legacy_pfx_signing_is_gone()
    {
        var root = Root();
        if (root == null)
            return;

        foreach (var script in new[] { "codesign.ps1", "sign-publish-artifacts.ps1", "dev-codesign.ps1" })
            Assert.False(File.Exists(Path.Combine(root, "scripts", script)), script);

        foreach (var file in new[]
                 {
                     Path.Combine(".github", "workflows", "ci.yml"),
                     Path.Combine("installer", "setup.iss"),
                     Path.Combine("installer", "build-release-setup.ps1"),
                     Path.Combine("scripts", "publish-release.ps1"),
                 })
        {
            var text = File.ReadAllText(Path.Combine(root, file));
            Assert.DoesNotContain("CODESIGN_", text, StringComparison.Ordinal);
            Assert.DoesNotContain("SignPfxPath", text, StringComparison.Ordinal);
            Assert.DoesNotContain("CertSubject", text, StringComparison.Ordinal);
            Assert.DoesNotContain("SignTool=", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Release_workflow_signs_through_signpath_and_verifies()
    {
        var root = Root();
        if (root == null)
            return;

        var release = File.ReadAllText(Path.Combine(root, ".github", "workflows", "release.yml"));
        Assert.Contains("signpath/github-action-submit-signing-request@", release, StringComparison.Ordinal);
        Assert.Contains("artifact-configuration-slug: binaries", release, StringComparison.Ordinal);
        Assert.Contains("artifact-configuration-slug: installer", release, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", release, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(root, "docs", "CODE_SIGNING_POLICY.md")));
        var license = File.ReadAllText(Path.Combine(root, "LICENSE.txt"));
        Assert.Contains("GNU GENERAL PUBLIC LICENSE", license, StringComparison.Ordinal);
        Assert.Contains("Version 3, 29 June 2007", license, StringComparison.Ordinal);
    }
}
