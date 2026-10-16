// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;
using optiSCAN.Models;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>
/// Détections faites par l'hôte SYSTEM. Le service tourne en session 0 : il ne peut ni afficher
/// de notification ni écrire dans l'historique d'un utilisateur. Les sessions viennent donc
/// chercher ici, par le pipe, ce qui a été détecté depuis leur dernier passage.
/// <para>
/// Les 200 dernières détections sont gardées en mémoire et dans
/// <c>%ProgramData%\optiSCAN\detections.json</c> (SYSTEM et Administrateurs), pour qu'une
/// détection faite avant l'ouverture de session soit encore montrée.
/// </para>
/// </summary>
public sealed class ServiceDetectionLog
{
    internal const int Capacity = 200;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private readonly object _gate = new();
    private readonly List<ServiceDetectionItem> _items = new();
    private readonly List<string> _paths = new();
    private readonly string? _storePath;
    private long _lastSequence;

    internal static ServiceDetectionLog Shared { get; } = new(DefaultStorePath());

    internal ServiceDetectionLog(string? storePath)
    {
        _storePath = storePath;
        Load();
    }

    private static string? DefaultStorePath()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!identity.IsSystem || !OptiScanProgramData.EnsureTrusted())
                return null;
            return Path.Combine(OptiScanProgramData.DirectoryPath, "detections.json");
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return null;
        }
    }

    internal long LatestSequence
    {
        get { lock (_gate) return _lastSequence; }
    }

    /// <summary>Enregistre une détection et rend son numéro.</summary>
    internal long Record(ThreatInfo threat)
    {
        lock (_gate)
        {
            // Numéros fondés sur l'horloge : un hôte relancé ne réutilise pas des numéros déjà
            // vus par une session (sinon ses nouvelles détections seraient tenues pour lues).
            var seq = Math.Max(_lastSequence + 1, DateTime.UtcNow.Ticks);
            _lastSequence = seq;
            _items.Add(new ServiceDetectionItem
            {
                Sequence = seq,
                DetectedAtUtc = DateTime.UtcNow,
                VirusName = threat.VirusName,
                Engine = threat.DetectedBy,
                FileName = threat.FileName,
                Quarantined = threat.Status == ThreatStatus.Quarantined,
            });
            _paths.Add(threat.FilePath);
            while (_items.Count > Capacity)
            {
                _items.RemoveAt(0);
                _paths.RemoveAt(0);
            }

            Save();
            return seq;
        }
    }

    /// <summary>
    /// Détections postérieures à <paramref name="since"/>. Le chemin complet n'est rendu qu'à un
    /// administrateur élevé, ou si le fichier est dans le profil de <paramref name="clientSid"/>.
    /// </summary>
    internal List<ServiceDetectionItem> Since(long since, string? clientSid, bool elevatedAdministrator)
    {
        var profile = elevatedAdministrator ? null : ProfileDirectoryOf(clientSid);
        lock (_gate)
        {
            var list = new List<ServiceDetectionItem>();
            for (var i = 0; i < _items.Count; i++)
            {
                var item = _items[i];
                if (item.Sequence <= since)
                    continue;
                var path = _paths[i];
                list.Add(new ServiceDetectionItem
                {
                    Sequence = item.Sequence,
                    DetectedAtUtc = item.DetectedAtUtc,
                    VirusName = item.VirusName,
                    Engine = item.Engine,
                    FileName = item.FileName,
                    Quarantined = item.Quarantined,
                    FullPath = elevatedAdministrator || IsUnder(path, profile) ? path : null,
                });
            }

            return list;
        }
    }

    internal static bool IsUnder(string? path, string? folder)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(folder))
            return false;
        var root = folder.TrimEnd('\\', '/');
        return path.Length > root.Length + 1
            && path.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            && (path[root.Length] == '\\' || path[root.Length] == '/');
    }

    /// <summary>Dossier de profil d'un compte, lu dans le registre machine (ProfileList).</summary>
    private static string? ProfileDirectoryOf(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid) || !sid.StartsWith("S-1-5-", StringComparison.Ordinal) || !OperatingSystem.IsWindows())
            return null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
            return key?.GetValue("ProfileImagePath") is string p
                ? Environment.ExpandEnvironmentVariables(p)
                : null;
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return null;
        }
    }

    private sealed class Stored
    {
        public List<ServiceDetectionItem> Items { get; set; } = new();
        public List<string> Paths { get; set; } = new();
    }

    private void Load()
    {
        if (_storePath == null || !File.Exists(_storePath))
            return;
        try
        {
            if (!OptiScanProgramData.IsTrustedFile(_storePath))
                return;
            var stored = JsonSerializer.Deserialize<Stored>(File.ReadAllText(_storePath), JsonOptions);
            if (stored == null || stored.Items.Count != stored.Paths.Count)
                return;
            var skip = Math.Max(0, stored.Items.Count - Capacity);
            _items.AddRange(stored.Items.Skip(skip));
            _paths.AddRange(stored.Paths.Skip(skip));
            _lastSequence = _items.Count > 0 ? _items[^1].Sequence : 0;
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ServiceDetectionLog", "Lecture des détections", ex);
        }
    }

    private void Save()
    {
        if (_storePath == null)
            return;
        try
        {
            AtomicFile.WriteAllText(_storePath, JsonSerializer.Serialize(
                new Stored { Items = _items.ToList(), Paths = _paths.ToList() }, JsonOptions));
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ServiceDetectionLog", "Écriture des détections", ex);
        }
    }
}
