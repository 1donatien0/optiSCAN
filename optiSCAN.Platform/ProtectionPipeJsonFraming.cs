// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using System.Text.Json;

namespace optiSCAN.Platform;

public static class ProtectionPipeJsonFraming
{
    /// <summary>Taille maximale d'un message JSON sur le pipe.</summary>
    public const int DefaultMaxBytes = 1024 * 1024;

    /// <summary>
    /// Lit un message JSON jusqu'à sa fin. La fin d'un objet ou d'un tableau est repérée au fil
    /// des octets reçus (profondeur, chaînes, échappements), en un seul passage : l'ancienne
    /// lecture ré-analysait tout le tampon à chaque bloc, soit jusqu'à 128 analyses d'un message
    /// de 1 Mo envoyé par n'importe quel compte (audit A10). Le format sur le fil ne change pas.
    /// </summary>
    public static async Task<string> ReadJsonPayloadAsync(Stream stream, CancellationToken ct, int maxBytes = DefaultMaxBytes)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        var scanner = new JsonEndScanner();

        while (ms.Length < maxBytes)
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
            idle.CancelAfter(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buf, idle.Token).ConfigureAwait(false);
            if (read <= 0)
                break;

            ms.Write(buf, 0, read);
            var state = scanner.Feed(buf.AsSpan(0, read));
            if (state == JsonEndScanner.State.Complete)
                return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);

            // Valeur racine qui n'est ni un objet ni un tableau : repli sur l'analyse complète.
            if (state == JsonEndScanner.State.Scalar)
            {
                var text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
                if (IsCompleteJson(text))
                    return text;
            }
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

    /// <summary>
    /// Repère la fin de la valeur racine d'un flux JSON UTF-8 sans le ré-analyser. Les octets
    /// multioctets UTF-8 sont tous ≥ 0x80 : ils ne peuvent pas être confondus avec les
    /// délimiteurs ASCII suivis ici.
    /// </summary>
    internal sealed class JsonEndScanner
    {
        internal enum State { Pending, Complete, Scalar }

        private int _depth;
        private bool _started;
        private bool _inString;
        private bool _escape;
        private bool _scalar;
        private bool _complete;

        internal State Feed(ReadOnlySpan<byte> data)
        {
            if (_scalar)
                return State.Scalar;
            if (_complete)
                return State.Complete;

            foreach (var b in data)
            {
                if (!_started)
                {
                    if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0xEF or 0xBB or 0xBF)
                        continue;
                    if (b is not ((byte)'{' or (byte)'['))
                    {
                        _scalar = true;
                        return State.Scalar;
                    }

                    _started = true;
                    _depth = 1;
                    continue;
                }

                if (_inString)
                {
                    if (_escape)
                        _escape = false;
                    else if (b == (byte)'\\')
                        _escape = true;
                    else if (b == (byte)'"')
                        _inString = false;
                    continue;
                }

                switch (b)
                {
                    case (byte)'"':
                        _inString = true;
                        break;
                    case (byte)'{':
                    case (byte)'[':
                        _depth++;
                        break;
                    case (byte)'}':
                    case (byte)']':
                        if (--_depth == 0)
                        {
                            _complete = true;
                            return State.Complete;
                        }
                        break;
                }
            }

            return State.Pending;
        }
    }
}
