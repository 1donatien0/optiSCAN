// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace optiSCAN.Services;

/// <summary>
/// Répit accordé à un fichier que l'utilisateur vient de restaurer depuis la quarantaine.
/// Sans lui, le temps réel de la session le détectait dès son écriture et, quarantaine
/// automatique active, le remettait aussitôt en quarantaine.
/// <para>
/// Gardé en mémoire seulement (rien qu'un autre processus puisse écrire), lié au chemin exact
/// et à l'empreinte SHA-256 du contenu restauré, pour 15 minutes. Le temps réel du service
/// SYSTEM n'en tient pas compte : un compte standard ne peut pas y soustraire un fichier.
/// </para>
/// </summary>
public static class RestoredContentGrace
{
    internal static readonly TimeSpan Duration = TimeSpan.FromMinutes(15);
    private const int MaxEntries = 64;

    private static readonly object Gate = new();
    private static readonly Dictionary<string, (string Sha256, DateTime ExpiresUtc)> Entries =
        new(StringComparer.OrdinalIgnoreCase);

    public static void Register(string path, string sha256) => Register(path, sha256, DateTime.UtcNow);

    internal static void Register(string path, string sha256, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(sha256))
            return;
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ignored) when (!ignored.IsFatal()) { return; }

        lock (Gate)
        {
            Prune(nowUtc);
            if (Entries.Count >= MaxEntries)
                Entries.Remove(Entries.OrderBy(e => e.Value.ExpiresUtc).First().Key);
            Entries[full] = (sha256, nowUtc + Duration);
        }
    }

    public static bool IsGranted(string path, string sha256) => IsGranted(path, sha256, DateTime.UtcNow);

    internal static bool IsGranted(string path, string sha256, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(sha256))
            return false;
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ignored) when (!ignored.IsFatal()) { return false; }

        lock (Gate)
        {
            Prune(nowUtc);
            return Entries.TryGetValue(full, out var entry)
                && string.Equals(entry.Sha256, sha256, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static void ResetForTests()
    {
        lock (Gate)
            Entries.Clear();
    }

    private static void Prune(DateTime nowUtc)
    {
        foreach (var key in Entries.Where(e => e.Value.ExpiresUtc <= nowUtc).Select(e => e.Key).ToList())
            Entries.Remove(key);
    }
}
