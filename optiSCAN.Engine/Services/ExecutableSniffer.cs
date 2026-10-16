// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Services
{
    /// <summary>
    /// Reconnaît un exécutable Windows (format PE) à son contenu, quelle que soit son extension.
    /// </summary>
    /// <remarks>
    /// Le chargeur Windows exécute un PE nommé <c>facture.dat</c> ou <c>x.tmp</c>
    /// (<c>rundll32 x.dat,Entry</c>, <c>CreateProcess</c>), et c'est la forme habituelle d'un
    /// second étage déposé par un dropper. On lit l'en-tête DOS (<c>MZ</c>), puis la signature
    /// <c>PE\0\0</c> à l'offset <c>e_lfanew</c> : deux lectures de quelques octets, sans charger
    /// le fichier. Un simple « MZ » en tête d'un fichier texte ne suffit pas.
    /// </remarks>
    internal static class ExecutableSniffer
    {
        private const int DosHeaderSize = 64;
        private const int LfanewOffset = 0x3C;

        /// <summary>
        /// Plus petit <c>e_lfanew</c> accepté. Le chargeur Windows admet un en-tête PE qui
        /// chevauche l'en-tête DOS (au-delà de la signature <c>MZ</c> et de ses deux octets) :
        /// exiger 64 laissait passer ces binaires renommés en <c>.dat</c> (audit V10).
        /// </summary>
        internal const int MinPeHeaderOffset = 4;

        /// <summary>Au-delà, <c>e_lfanew</c> est jugé invalide (les PE réels le placent bien avant).</summary>
        internal const int MaxPeHeaderOffset = 64 * 1024;

        /// <summary>Lit l'en-tête par la poignée donnée (déjà ouverte et contrôlée par l'appelant).</summary>
        internal static bool IsPortableExecutable(SafeFileHandle handle)
        {
            try
            {
                return Check((offset, buffer) => RandomAccess.Read(handle, buffer, offset));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                return false;
            }
        }

        /// <summary>
        /// Ouvre le fichier sans gêner son auteur (partage lecture, écriture et suppression),
        /// lit l'en-tête et referme. Faux si le fichier est illisible.
        /// </summary>
        internal static bool IsPortableExecutable(string path)
        {
            try
            {
                using var stream = new FileStream(
                    path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, bufferSize: 1);
                return IsPortableExecutable(stream);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                           or ArgumentException or NotSupportedException)
            {
                return false;
            }
        }

        /// <summary>Lit l'en-tête depuis un flux positionnable.</summary>
        internal static bool IsPortableExecutable(Stream stream)
        {
            if (!stream.CanSeek || !stream.CanRead)
                return false;
            return Check((offset, buffer) =>
            {
                stream.Seek(offset, SeekOrigin.Begin);
                var total = 0;
                int read;
                while (total < buffer.Length && (read = stream.Read(buffer[total..])) > 0)
                    total += read;
                return total;
            });
        }

        private delegate int ReadAt(long offset, Span<byte> buffer);

        private static bool Check(ReadAt read)
        {
            Span<byte> dos = stackalloc byte[DosHeaderSize];
            if (read(0, dos) < DosHeaderSize || dos[0] != (byte)'M' || dos[1] != (byte)'Z')
                return false;

            var lfanew = BinaryPrimitives.ReadInt32LittleEndian(dos[LfanewOffset..]);
            if (lfanew < MinPeHeaderOffset || lfanew > MaxPeHeaderOffset)
                return false;

            Span<byte> signature = stackalloc byte[4];
            return read(lfanew, signature) == 4
                && signature[0] == (byte)'P' && signature[1] == (byte)'E'
                && signature[2] == 0 && signature[3] == 0;
        }
    }
}
