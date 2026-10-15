using System.IO;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Services;

/// <summary>Fichier de restauration déjà créé, que l'appelant remplit.</summary>
internal interface IRestoreTarget : IDisposable
{
    Stream Stream { get; }

    /// <summary>Chemin réel du fichier créé.</summary>
    string FinalPath { get; }

    /// <summary>Abandonne le fichier : il est supprimé à la fermeture.</summary>
    void Discard();
}

/// <summary>
/// Création des fichiers restaurés depuis la quarantaine (interface et service).
/// <list type="bullet">
/// <item>Le fichier est créé neuf (<c>FILE_CREATE</c>) : jamais d'écrasement.</item>
/// <item>Le chemin est parcouru nom par nom sans traverser de jonction ni de lien
/// (<see cref="SafePathDelete.CreateNew"/>) : l'écriture ne peut pas être redirigée.</item>
/// <item>Le chemin réel est relu ; s'il diffère du chemin demandé ou désigne un dossier
/// système, le fichier est supprimé par la même poignée.</item>
/// </list>
/// </summary>
internal static class RestoreFileWriter
{
    /// <summary>Crée le fichier (et ses dossiers parents manquants). Null si refusé ou déjà présent.</summary>
    internal static IRestoreTarget? TryCreate(string fullPath)
    {
        var handle = TryCreateHandle(fullPath);
        return handle == null ? null : Validate(handle, fullPath);
    }

    /// <summary>Étape d'ouverture seule, à appeler sous usurpation d'identité si besoin.</summary>
    internal static SafeFileHandle? TryCreateHandle(string fullPath)
    {
        try
        {
            if (QuarantineManager.IsSensitivePath(fullPath))
                return null;
            var dir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);
            return SafePathDelete.CreateNew(fullPath);
        }
        catch (Exception ex)
        {
            AppLogger.Debug("RestoreFileWriter", "Création refusée : " + ex.Message);
            return null;
        }
    }

    /// <summary>Contrôle du chemin réel après ouverture ; supprime le fichier s'il est refusé.</summary>
    internal static IRestoreTarget? Validate(SafeFileHandle handle, string requestedPath)
    {
        var final = RealTimePathGuard.FinalPath(handle);
        var normalized = final == null ? null : RealTimePathGuard.NormalizeFinalPath(final);
        string requested;
        try { requested = Path.GetFullPath(requestedPath); }
        catch { requested = string.Empty; }

        if (normalized == null
            || QuarantineManager.IsSensitivePath(normalized)
            || !string.Equals(normalized, requested, StringComparison.OrdinalIgnoreCase))
        {
            AppLogger.Warn("RestoreFileWriter",
                "Restauration annulée : le fichier créé ne se trouve pas à l'emplacement demandé.");
            SafePathDelete.SetDeleteDisposition(handle, true);
            handle.Dispose();
            return null;
        }

        return new HandleRestoreTarget(handle, normalized);
    }

    private sealed class HandleRestoreTarget : IRestoreTarget
    {
        private readonly SafeFileHandle _handle;
        private readonly FileStream _stream;

        public HandleRestoreTarget(SafeFileHandle handle, string finalPath)
        {
            _handle = handle;
            _stream = new FileStream(handle, FileAccess.Write);
            FinalPath = finalPath;
        }

        public Stream Stream => _stream;

        public string FinalPath { get; }

        public void Discard()
        {
            try { _stream.Flush(); } catch { /* fichier abandonné */ }
            SafePathDelete.SetDeleteDisposition(_handle, true);
        }

        public void Dispose() => _stream.Dispose();
    }
}
