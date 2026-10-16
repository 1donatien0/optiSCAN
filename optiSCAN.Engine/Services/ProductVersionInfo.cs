// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Reflection;

namespace optiSCAN.Services
{
    /// <summary>
    /// Convention alignée sur l’historique produit (README) :
    /// <list type="bullet">
    /// <item><description><b>vM.m</b> — nom de release (ex. v3.1).</description></item>
    /// <item><description><b>M.m.p</b> — identifiant de build / assembly / installateur (ex. 3.1.0).</description></item>
    /// </list>
    /// </summary>
    internal static class ProductVersionInfo
    {
        private static readonly Assembly Asm = Assembly.GetExecutingAssembly();
        private static readonly Version? AsmNameVersion = Asm.GetName().Version;

        /// <summary>Triplet sémantique affiché (barre latérale, User-Agent HTTP, propriétés fichier).</summary>
        public static string SemVer
        {
            get
            {
                var info = Asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                    ?.InformationalVersion?.Split('+', 2)[0].Trim();
                if (!string.IsNullOrEmpty(info))
                    return info;
                return AsmNameVersion is null ? "0.0.0"
                    : $"{AsmNameVersion.Major}.{AsmNameVersion.Minor}.{Math.Max(0, AsmNameVersion.Build)}";
            }
        }

        /// <summary>Nom de release type README (v3.1).</summary>
        public static string ReleaseLabel =>
            AsmNameVersion is null ? "v0.0" : $"v{AsmNameVersion.Major}.{AsmNameVersion.Minor}";

        public static string HttpUserAgent => $"optiSCAN/{SemVer}";

        /// <summary>Marqueur freshclam.conf (numéro de version majeure seul, ex. v3).</summary>
        public static int ConfMarkerMajor => AsmNameVersion?.Major ?? 0;
    }
}
