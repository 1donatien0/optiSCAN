// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using PdfSharp.Fonts;

namespace optiSCAN.Services;

/// <summary>
/// Polices du rapport PDF lues dans le dossier des polices de Windows. Le résolveur intégré de
/// PDFsharp (build Core) ne connaît que quelques polices standard ; Segoe UI n'en fait pas partie.
/// Repli sur Arial, présent sur toutes les éditions de Windows.
/// </summary>
internal sealed class PdfFontResolver : IFontResolver
{
    private static readonly string FontsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Fonts);

    // Fichier par famille et style : régulier, gras, italique, gras italique.
    private static readonly Dictionary<string, string[]> Families = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Segoe UI"] = new[] { "segoeui.ttf", "segoeuib.ttf", "segoeuii.ttf", "segoeuiz.ttf" },
        ["Arial"] = new[] { "arial.ttf", "arialbd.ttf", "ariali.ttf", "arialbi.ttf" },
    };

    public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic)
    {
        var index = (bold ? 1 : 0) + (italic ? 2 : 0);
        foreach (var family in new[] { familyName, "Segoe UI", "Arial" })
        {
            if (!Families.TryGetValue(family, out var files))
                continue;
            var file = files[index];
            if (File.Exists(Path.Combine(FontsDirectory, file)))
                return new FontResolverInfo(file);
            // Style absent : la version régulière, simulée en gras ou en italique.
            if (File.Exists(Path.Combine(FontsDirectory, files[0])))
                return new FontResolverInfo(files[0], bold, italic);
        }
        return null;
    }

    public byte[]? GetFont(string faceName)
    {
        var path = Path.Combine(FontsDirectory, Path.GetFileName(faceName));
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }
}
