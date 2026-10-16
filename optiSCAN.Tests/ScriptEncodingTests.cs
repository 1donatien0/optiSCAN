// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Tests;

/// <summary>
/// Windows PowerShell 5.1 lit un script sans BOM en ANSI : un tiret cadratin UTF-8 (E2 80 94)
/// y devient « â€” », dont le dernier octet est un guillemet typographique fermant pour
/// PowerShell. publish-release.ps1 échouait ainsi à l'analyse (« terminateur manquant »).
/// </summary>
public sealed class ScriptEncodingTests
{
    [Fact]
    public void Scripts_with_non_ascii_text_carry_a_utf8_bom()
    {
        var dir = AppContext.BaseDirectory;
        string? root = null;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln"))) { root = dir; break; }
        if (root == null)
            return;

        var offenders = new List<string>();
        foreach (var folder in new[] { "scripts", "installer" })
        {
            var path = Path.Combine(root, folder);
            if (!Directory.Exists(path))
                continue;
            foreach (var file in Directory.EnumerateFiles(path, "*.ps1", SearchOption.TopDirectoryOnly))
            {
                var bytes = File.ReadAllBytes(file);
                var bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
                if (!bom && bytes.Any(b => b > 0x7F))
                    offenders.Add(Path.GetFileName(file));
            }
        }

        Assert.True(offenders.Count == 0, "Scripts sans BOM UTF-8 : " + string.Join(", ", offenders));
    }
}
