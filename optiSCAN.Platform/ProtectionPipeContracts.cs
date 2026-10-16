// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json.Serialization;

namespace optiSCAN.Platform;

/// <summary>Noms de pipes utilisés par les clients et le serveur. Voir <see cref="ProtectionIdentifiers"/>.</summary>
public static class ProtectionPipeNames
{
    public const string Protection = ProtectionIdentifiers.PipeName;
}

public sealed class ProtectionPipeRequest
{
    /// <summary>
    /// Version du protocole IPC parlée par le client (<see cref="ProtectionIdentifiers.ProtocolVersion"/>).
    /// Absente = client historique, traité comme la version 1.
    /// </summary>
    [JsonPropertyName("proto")]
    public int? ProtocolVersion { get; set; }

    [JsonPropertyName("op")]
    public string Operation { get; set; } = string.Empty;

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("buffer_b64")]
    public string? BufferBase64 { get; set; }

    [JsonPropertyName("content_name")]
    public string? ContentName { get; set; }

    /// <summary>Requis pour <see cref="ProtectionPipeOperations.Shutdown"/>.</summary>
    [JsonPropertyName("auth")]
    public string? AuthToken { get; set; }

    [JsonPropertyName("rt")]
    public bool? RealTimeEnabled { get; set; }

    [JsonPropertyName("monitor")]
    public bool? ProcessMonitorEnabled { get; set; }

    [JsonPropertyName("quarantine")]
    public bool? AutoQuarantineEnabled { get; set; }

    [JsonPropertyName("signatures")]
    public bool? SignatureAutoUpdateEnabled { get; set; }

    [JsonPropertyName("removable")]
    public bool? RemovableDriveScanEnabled { get; set; }

    /// <summary>Entrée visée par <see cref="ProtectionPipeOperations.QuarantineRestore"/> ou <see cref="ProtectionPipeOperations.QuarantineDelete"/>.</summary>
    [JsonPropertyName("qid")]
    public string? QuarantineId { get; set; }

    /// <summary>
    /// Dossier de restauration choisi par l'administrateur. Absent : emplacement d'origine.
    /// </summary>
    [JsonPropertyName("dest")]
    public string? DestinationFolder { get; set; }

    /// <summary>
    /// <see cref="ProtectionPipeOperations.RecentDetections"/> : numéro de la dernière détection
    /// déjà vue par le client ; seules les suivantes sont rendues.
    /// </summary>
    [JsonPropertyName("since")]
    public long? SinceSequence { get; set; }
}

/// <summary>Détection faite par le service SYSTEM, telle qu'une session la reçoit.</summary>
public sealed class ServiceDetectionItem
{
    /// <summary>Numéro croissant, propre à la machine.</summary>
    [JsonPropertyName("seq")]
    public long Sequence { get; set; }

    [JsonPropertyName("at")]
    public DateTime DetectedAtUtc { get; set; }

    [JsonPropertyName("threat")]
    public string VirusName { get; set; } = string.Empty;

    [JsonPropertyName("engine")]
    public string? Engine { get; set; }

    /// <summary>Nom du fichier, toujours fourni.</summary>
    [JsonPropertyName("file")]
    public string FileName { get; set; } = string.Empty;

    /// <summary>
    /// Chemin complet : seulement pour un administrateur élevé, ou si le fichier est dans le
    /// profil du compte qui demande. Les chemins des autres comptes ne sortent pas du service.
    /// </summary>
    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FullPath { get; set; }

    [JsonPropertyName("quarantined")]
    public bool Quarantined { get; set; }
}

/// <summary>Élément de la quarantaine du service, tel que le reçoit l'interface d'administration.</summary>
public sealed class ServiceQuarantineItem
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("path")]
    public string OriginalPath { get; set; } = string.Empty;

    [JsonPropertyName("threat")]
    public string VirusName { get; set; } = string.Empty;

    [JsonPropertyName("at")]
    public DateTime QuarantinedAt { get; set; }

    [JsonPropertyName("size")]
    public long OriginalSize { get; set; }

    [JsonIgnore]
    public string FileName => System.IO.Path.GetFileName(OriginalPath);
}

public sealed class ProtectionPipeResponse
{
    /// <summary>Version du protocole IPC parlée par le serveur.</summary>
    [JsonPropertyName("proto")]
    public int ProtocolVersion { get; set; } = ProtectionIdentifiers.ProtocolVersion;

    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("clean")]
    public bool Clean { get; set; } = true;

    [JsonPropertyName("threat")]
    public string? ThreatName { get; set; }

    [JsonPropertyName("engine")]
    public string? Engine { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("incomplete")]
    public bool Incomplete { get; set; }

    /// <summary>Nombre d'éléments (résumé ou purge de la quarantaine du service).</summary>
    [JsonPropertyName("count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Count { get; set; }

    /// <summary>Taille d'origine cumulée des éléments de la quarantaine du service.</summary>
    [JsonPropertyName("bytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? TotalBytes { get; set; }

    /// <summary>Durée de conservation appliquée par le service, en jours.</summary>
    [JsonPropertyName("retention")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RetentionDays { get; set; }

    [JsonPropertyName("entries")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ServiceQuarantineItem>? Entries { get; set; }

    /// <summary>Détections du service postérieures à <see cref="ProtectionPipeRequest.SinceSequence"/>.</summary>
    [JsonPropertyName("detections")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ServiceDetectionItem>? Detections { get; set; }

    /// <summary>Numéro de la détection la plus récente du service (0 : aucune).</summary>
    [JsonPropertyName("latest")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? LatestSequence { get; set; }

    /// <summary>
    /// Temps réel du service : nombre de dossiers surveillés en défaut (0 : complet), ou null si
    /// le temps réel du service est arrêté. Aucun chemin : la réponse va à tout compte.
    /// </summary>
    [JsonPropertyName("rt_degraded")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RealTimeDegradedFolders { get; set; }

    public static ProtectionPipeResponse SuccessClean() => new() { Ok = true, Clean = true };

    public static ProtectionPipeResponse Threat(string name, string? engine = null, bool incomplete = false) => new()
    {
        Ok = true,
        Clean = false,
        ThreatName = name,
        Engine = engine,
        Incomplete = incomplete,
        Message = incomplete ? "Scan incomplet : une partie du contenu n'a pas pu être vérifiée." : null,
    };

    public static ProtectionPipeResponse Error(string message) => new() { Ok = false, Message = message };
}

public static class ProtectionPipeOperations
{
    public const string Ping = "ping";
    public const string ScanPath = "scan_path";
    public const string ScanBuffer = "scan_buffer";
    public const string Shutdown = "shutdown";
    public const string GetStatus = "status";
    public const string SetPolicy = "set_policy";

    // Quarantaine du service (SYSTEM). Le résumé (nombre, taille) est ouvert à tout compte
    // authentifié ; la liste et les actions exigent un administrateur élevé.
    // Opérations ajoutées sans changer ProtocolVersion : un service plus ancien répond
    // « Opération inconnue », que l'interface traite comme « fonction absente ».
    public const string QuarantineSummary = "quarantine_summary";
    public const string QuarantineList = "quarantine_list";
    public const string QuarantineRestore = "quarantine_restore";
    public const string QuarantineDelete = "quarantine_delete";
    public const string QuarantinePurge = "quarantine_purge";

    /// <summary>
    /// Détections récentes du service, pour que la session les affiche (le service SYSTEM ne
    /// peut pas notifier l'utilisateur lui-même). Ouverte à tout compte authentifié ; les chemins
    /// complets sont filtrés par compte.
    /// </summary>
    public const string RecentDetections = "recent_detections";
}
