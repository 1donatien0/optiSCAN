// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Tests;

/// <summary>Tout le code d'optiSCAN est sous GPL-3.0-or-later et le déclare en tête de fichier.</summary>
public sealed class LicenseHeaderTests
{
    [Fact]
    public void Every_first_party_source_file_declares_the_gpl()
    {
        var dir = AppContext.BaseDirectory;
        string? root = null;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln"))) { root = dir; break; }
        if (root == null)
            return;

        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".cs", ".cpp", ".h", ".c", ".rc", ".ps1", ".iss" };
        var missing = new List<string>();
        foreach (var folder in new[] { "optiSCAN", "optiSCAN.Engine", "optiSCAN.Platform", "optiSCAN.Service", "optiSCAN.Host", "optiSCAN.Tests", "native", "scripts", "installer" })
        {
            var path = Path.Combine(root, folder);
            if (!Directory.Exists(path))
                continue;
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                var sep = Path.DirectorySeparatorChar;
                if (!extensions.Contains(Path.GetExtension(file))
                    || file.Contains(sep + "obj" + sep) || file.Contains(sep + "bin" + sep))
                    continue;
                using var reader = new StreamReader(file);
                var head = new char[400];
                var read = reader.Read(head, 0, head.Length);
                if (!new string(head, 0, read).Contains("SPDX-License-Identifier: GPL-3.0-or-later", StringComparison.Ordinal))
                    missing.Add(Path.GetRelativePath(root, file));
            }
        }

        Assert.True(missing.Count == 0, "Sans en-tête GPL : " + string.Join(", ", missing.Take(20)));
    }
}
