// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using optiSCAN.Platform;

namespace optiSCAN.Tests;

public sealed class ProtectionPipeJsonFramingTests
{
    /// <summary>Flux qui rend les octets par petits blocs, puis reste ouvert (comme un pipe).</summary>
    private sealed class ChunkedStream(byte[] data, int chunk) : Stream
    {
        private int _pos;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _pos; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_pos >= data.Length)
            {
                // Pipe ouvert sans nouvelle donnée : seule une fin de message détectée évite l'attente.
                await Task.Delay(Timeout.Infinite, ct);
            }

            var n = Math.Min(Math.Min(chunk, buffer.Length), data.Length - _pos);
            data.AsMemory(_pos, n).CopyTo(buffer);
            _pos += n;
            return n;
        }
    }

    [Theory]
    [InlineData("{\"op\":\"ping\"}", 1)]
    [InlineData("{\"op\":\"ping\"}", 4096)]
    [InlineData("{\"path\":\"C:\\\\a}b{c\\\"]\",\"x\":[1,{\"y\":2}]}", 3)]
    [InlineData("\uFEFF{\"op\":\"é}\"}", 2)]
    public async Task Complete_message_is_returned_without_waiting_for_more_data(string json, int chunk)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));

        var text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(new ChunkedStream(bytes, chunk), cts.Token);

        Assert.Equal(json, text);
    }

    [Fact]
    public void Scanner_ignores_braces_inside_strings_and_escapes()
    {
        var scanner = new ProtectionPipeJsonFraming.JsonEndScanner();
        Assert.Equal(ProtectionPipeJsonFraming.JsonEndScanner.State.Pending,
            scanner.Feed(Encoding.UTF8.GetBytes("{\"a\":\"}\\\"}")));
        Assert.Equal(ProtectionPipeJsonFraming.JsonEndScanner.State.Complete,
            scanner.Feed(Encoding.UTF8.GetBytes("\"}")));
    }

    [Fact]
    public async Task One_megabyte_message_is_read_in_a_single_pass()
    {
        var json = "{\"buffer_b64\":\"" + new string('A', ProtectionPipeJsonFraming.DefaultMaxBytes - 64) + "\"}";
        var bytes = Encoding.UTF8.GetBytes(json);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var watch = System.Diagnostics.Stopwatch.StartNew();
        var text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(new ChunkedStream(bytes, 8192), cts.Token);
        watch.Stop();

        Assert.Equal(json.Length, text.Length);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), $"Lecture trop lente : {watch.Elapsed}");
    }
}
