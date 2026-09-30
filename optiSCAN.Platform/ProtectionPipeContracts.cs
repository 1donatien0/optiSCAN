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

    public static ProtectionPipeResponse SuccessClean() => new() { Ok = true, Clean = true };

    public static ProtectionPipeResponse Threat(string name, string? engine = null) => new()
    {
        Ok = true,
        Clean = false,
        ThreatName = name,
        Engine = engine,
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
}
