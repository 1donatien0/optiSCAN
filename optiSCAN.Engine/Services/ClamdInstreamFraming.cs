// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.IO;

namespace optiSCAN.Services;

/// <summary>
/// Découpe d'une requête clamd <c>zINSTREAM</c> : en-tête, puis blocs « longueur sur 4 octets
/// gros-boutiste + données », terminés par un bloc de longueur 0.
/// Les relais alternent « requête puis réponse » : ils doivent savoir où finit la requête,
/// sinon ils attendraient une réponse que clamd n'enverra qu'après le dernier bloc.
/// </summary>
internal sealed class ClamdInstreamFramer
{
    internal const int HeaderLength = 10;

    /// <summary>Plafond de sécurité côté relais, au-delà du StreamMaxLength de clamd.</summary>
    internal const long MaxRelayedBytes = 256L * 1024 * 1024;

    private static readonly byte[] ZHeader = "zINSTREAM\0"u8.ToArray();
    private static readonly byte[] NHeader = "nINSTREAM\n"u8.ToArray();

    private readonly byte[] _length = new byte[4];
    private int _headerLeft = HeaderLength;
    private int _lengthHave;
    private long _dataLeft;

    /// <summary>Vrai après le bloc de longueur 0.</summary>
    public bool Done { get; private set; }

    /// <summary>Total des données annoncées par les blocs.</summary>
    public long DataBytes { get; private set; }

    internal static bool IsInstreamHeader(ReadOnlySpan<byte> data) =>
        data.Length >= HeaderLength
        && (data[..HeaderLength].SequenceEqual(ZHeader) || data[..HeaderLength].SequenceEqual(NHeader));

    /// <summary>Le début lu peut encore devenir un en-tête INSTREAM complet.</summary>
    internal static bool IsInstreamHeaderPrefix(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0 || data.Length >= HeaderLength)
            return false;
        return ZHeader.AsSpan(0, data.Length).SequenceEqual(data)
            || NHeader.AsSpan(0, data.Length).SequenceEqual(data);
    }

    /// <summary>
    /// Avale des octets de la requête. Retourne combien appartiennent à la requête :
    /// tout, sauf ce qui suivrait le bloc final (protocole violé, ignoré).
    /// </summary>
    public int Consume(ReadOnlySpan<byte> data)
    {
        var i = 0;
        while (i < data.Length && !Done)
        {
            if (_headerLeft > 0)
            {
                var n = Math.Min(_headerLeft, data.Length - i);
                _headerLeft -= n;
                i += n;
                continue;
            }

            if (_dataLeft > 0)
            {
                var n = (int)Math.Min(_dataLeft, data.Length - i);
                _dataLeft -= n;
                i += n;
                continue;
            }

            _length[_lengthHave++] = data[i++];
            if (_lengthHave < 4)
                continue;

            _lengthHave = 0;
            var chunk = BinaryPrimitives.ReadUInt32BigEndian(_length);
            if (chunk == 0)
            {
                Done = true;
            }
            else
            {
                _dataLeft = chunk;
                DataBytes += chunk;
            }
        }

        return i;
    }

    /// <summary>Complète un en-tête INSTREAM coupé en plusieurs lectures.</summary>
    internal static async Task<int> CompleteHeaderAsync(Stream inbound, byte[] buffer, int read, CancellationToken ct)
    {
        while (IsInstreamHeaderPrefix(buffer.AsSpan(0, read)))
        {
            var more = await inbound.ReadAsync(buffer.AsMemory(read, HeaderLength - read), ct).ConfigureAwait(false);
            if (more <= 0)
                break;
            read += more;
        }

        return read;
    }

    internal static int CompleteHeader(Stream inbound, byte[] buffer, int read)
    {
        while (IsInstreamHeaderPrefix(buffer.AsSpan(0, read)))
        {
            var more = inbound.Read(buffer, read, HeaderLength - read);
            if (more <= 0)
                break;
            read += more;
        }

        return read;
    }

    /// <summary>
    /// Transmet toute la requête INSTREAM (déjà commencée dans <paramref name="first"/>).
    /// Retourne false si le client coupe avant la fin ou dépasse le plafond.
    /// </summary>
    internal static async Task<bool> ForwardRequestAsync(
        Stream inbound,
        Stream outbound,
        byte[] first,
        int firstCount,
        CancellationToken ct)
    {
        var framer = new ClamdInstreamFramer();
        var buffer = first;
        var count = firstCount;
        while (true)
        {
            var take = framer.Consume(buffer.AsSpan(0, count));
            if (framer.DataBytes > MaxRelayedBytes)
                return false;
            await outbound.WriteAsync(buffer.AsMemory(0, take), ct).ConfigureAwait(false);
            if (framer.Done)
            {
                await outbound.FlushAsync(ct).ConfigureAwait(false);
                return true;
            }

            count = await inbound.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (count <= 0)
                return false;
        }
    }

    internal static bool ForwardRequest(Stream inbound, Stream outbound, byte[] first, int firstCount)
    {
        var framer = new ClamdInstreamFramer();
        var buffer = first;
        var count = firstCount;
        while (true)
        {
            var take = framer.Consume(buffer.AsSpan(0, count));
            if (framer.DataBytes > MaxRelayedBytes)
                return false;
            outbound.Write(buffer, 0, take);
            if (framer.Done)
            {
                outbound.Flush();
                return true;
            }

            count = inbound.Read(buffer, 0, buffer.Length);
            if (count <= 0)
                return false;
        }
    }
}
