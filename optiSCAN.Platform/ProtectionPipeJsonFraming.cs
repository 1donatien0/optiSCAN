using System.Text;
using System.Text.Json;

namespace optiSCAN.Platform;

public static class ProtectionPipeJsonFraming
{
    /// <summary>Taille maximale d'un message JSON sur le pipe.</summary>
    public const int DefaultMaxBytes = 1024 * 1024;

    public static async Task<string> ReadJsonPayloadAsync(Stream stream, CancellationToken ct, int maxBytes = DefaultMaxBytes)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];

        while (ms.Length < maxBytes)
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
            idle.CancelAfter(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buf, idle.Token).ConfigureAwait(false);
            if (read <= 0)
                break;

            ms.Write(buf, 0, read);
            var text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            if (IsCompleteJson(text))
                return text;
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static bool IsCompleteJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;

        try
        {
            using var _ = JsonDocument.Parse(text);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
