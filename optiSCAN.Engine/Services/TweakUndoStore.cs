using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace optiSCAN.Services;

/// <summary>
/// Valeurs d'origine des réglages modifiés par le panneau Optimiser (audit A11). Seule la
/// première modification d'un réglage est enregistrée : appliquer deux fois un tweak ne fait
/// pas oublier l'état d'avant. <see cref="SystemTweaksService.UndoAll"/> les rétablit.
/// <para>
/// Fichier <c>%LOCALAPPDATA%\optiSCAN\tweaks-undo.json</c> du compte, comme les réglages
/// qu'il décrit (HKCU) : il ne contient que des noms de valeurs du registre et un GUID de
/// plan d'alimentation.
/// </para>
/// </summary>
public static class TweakUndoStore
{
    public sealed class RegistryOriginal
    {
        [JsonPropertyName("key")] public string Key { get; set; } = string.Empty;
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        [JsonPropertyName("existed")] public bool Existed { get; set; }
        [JsonPropertyName("value")] public int Value { get; set; }

        /// <summary>Valeur d'origine d'un autre type que DWORD : laissée telle quelle au rétablissement.</summary>
        [JsonPropertyName("other")] public bool NonDword { get; set; }
    }

    public sealed class Snapshot
    {
        [JsonPropertyName("registry")] public List<RegistryOriginal> Registry { get; set; } = new();
        [JsonPropertyName("powerPlan")] public string? PowerPlanGuid { get; set; }
        [JsonPropertyName("telemetry")] public bool TelemetryApplied { get; set; }

        [JsonIgnore]
        public bool IsEmpty => Registry.Count == 0 && PowerPlanGuid == null && !TelemetryApplied;
    }

    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Emplacement du fichier ; remplaçable par les tests.</summary>
    internal static string? PathOverride { get; set; }

    private static string StorePath => PathOverride ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "optiSCAN", "tweaks-undo.json");

    public static Snapshot Load()
    {
        lock (Gate)
            return LoadUnlocked();
    }

    public static bool HasPendingUndo => !Load().IsEmpty;

    /// <summary>Enregistre la valeur d'origine d'une valeur HKCU, si ce n'est pas déjà fait.</summary>
    public static void RecordRegistryOriginal(string key, string name, bool existed, int value, bool nonDword = false) =>
        Update(s =>
        {
            if (s.Registry.Exists(r => string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase)
                                    && string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)))
                return false;
            s.Registry.Add(new RegistryOriginal { Key = key, Name = name, Existed = existed, Value = value, NonDword = nonDword });
            return true;
        });

    public static void RecordPowerPlanOriginal(string planId) =>
        Update(s =>
        {
            if (s.PowerPlanGuid != null)
                return false;
            s.PowerPlanGuid = planId;
            return true;
        });

    public static void RecordTelemetryApplied() =>
        Update(s =>
        {
            if (s.TelemetryApplied)
                return false;
            s.TelemetryApplied = true;
            return true;
        });

    /// <summary>Remplace le contenu (après une annulation partielle : ce qui reste à rétablir).</summary>
    public static void Save(Snapshot snapshot)
    {
        lock (Gate)
            SaveUnlocked(snapshot);
    }

    private static void Update(Func<Snapshot, bool> change)
    {
        lock (Gate)
        {
            var snapshot = LoadUnlocked();
            if (change(snapshot))
                SaveUnlocked(snapshot);
        }
    }

    private static Snapshot LoadUnlocked()
    {
        try
        {
            var path = StorePath;
            if (!File.Exists(path))
                return new Snapshot();
            return JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(path), JsonOptions) ?? new Snapshot();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("TweakUndoStore", "Lecture", ex);
            return new Snapshot();
        }
    }

    private static void SaveUnlocked(Snapshot snapshot)
    {
        try
        {
            var path = StorePath;
            if (snapshot.IsEmpty)
            {
                if (File.Exists(path))
                    File.Delete(path);
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            AtomicFile.WriteAllText(path, JsonSerializer.Serialize(snapshot, JsonOptions));
        }
        catch (Exception ex)
        {
            AppLogger.Warn("TweakUndoStore", "Écriture", ex);
        }
    }
}
