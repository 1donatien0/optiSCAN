// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Flux INSTREAM : découpage de la requête par les relais, client, et lecture de la réponse.
/// Aucun de ces tests ne dépend de clamd ni d'un AppContainer.
/// </summary>
public sealed class ClamdInstreamTests
{
    private static byte[] BuildRequest(byte[] content, int chunk)
    {
        using var ms = new MemoryStream();
        ms.Write("zINSTREAM\0"u8);
        for (var i = 0; i < content.Length; i += chunk)
        {
            var n = Math.Min(chunk, content.Length - i);
            var len = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(len, (uint)n);
            ms.Write(len);
            ms.Write(content, i, n);
        }
        ms.Write(new byte[4]);
        return ms.ToArray();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(4096)]
    public void Framer_finds_the_end_whatever_the_read_boundaries(int readSize)
    {
        var content = Enumerable.Range(0, 10_000).Select(i => (byte)(i % 251)).ToArray();
        var request = BuildRequest(content, 1000);
        var framer = new ClamdInstreamFramer();

        var consumed = 0;
        while (!framer.Done && consumed < request.Length)
        {
            var slice = request.AsSpan(consumed, Math.Min(readSize, request.Length - consumed));
            consumed += framer.Consume(slice);
        }

        Assert.True(framer.Done);
        Assert.Equal(request.Length, consumed);
        Assert.Equal(content.Length, framer.DataBytes);
    }

    [Fact]
    public void Framer_ignores_bytes_after_the_final_block()
    {
        var request = BuildRequest("abc"u8.ToArray(), 2).Concat("garbage"u8.ToArray()).ToArray();
        var framer = new ClamdInstreamFramer();

        var take = framer.Consume(request);

        Assert.True(framer.Done);
        Assert.Equal(request.Length - "garbage".Length, take);
    }

    [Theory]
    [InlineData("zINSTREAM\0", true)]
    [InlineData("nINSTREAM\n", true)]
    [InlineData("zPING\0", false)]
    [InlineData("SCAN C:\\x", false)]
    public void Header_detection(string text, bool expected) =>
        Assert.Equal(expected, ClamdInstreamFramer.IsInstreamHeader(Encoding.ASCII.GetBytes(text)));

    [Fact]
    public void Header_prefix_is_completed_from_following_reads()
    {
        var inbound = new TrickleStream("INSTREAM\0"u8.ToArray(), 1);
        var buffer = new byte[64];
        buffer[0] = (byte)'z';

        var read = ClamdInstreamFramer.CompleteHeader(inbound, buffer, 1);

        Assert.Equal(ClamdInstreamFramer.HeaderLength, read);
        Assert.True(ClamdInstreamFramer.IsInstreamHeader(buffer.AsSpan(0, read)));
    }

    [Fact]
    public async Task Relay_forwards_the_whole_request_before_waiting_for_the_reply()
    {
        var content = Enumerable.Range(0, 70_000).Select(i => (byte)i).ToArray();
        var request = BuildRequest(content, 65_536);
        var first = new byte[8192];
        Array.Copy(request, first, ClamdInstreamFramer.HeaderLength);
        var inbound = new TrickleStream(request[ClamdInstreamFramer.HeaderLength..], 5000);
        using var outbound = new MemoryStream();

        var ok = await ClamdInstreamFramer.ForwardRequestAsync(inbound, outbound, first, ClamdInstreamFramer.HeaderLength, CancellationToken.None);

        Assert.True(ok);
        Assert.Equal(request, outbound.ToArray());
    }

    [Fact]
    public void Relay_sync_variant_matches()
    {
        var request = BuildRequest(new byte[20_000], 4096);
        var first = new byte[8192];
        Array.Copy(request, first, 100);
        var inbound = new TrickleStream(request[100..], 333);
        using var outbound = new MemoryStream();

        Assert.True(ClamdInstreamFramer.ForwardRequest(inbound, outbound, first, 100));
        Assert.Equal(request, outbound.ToArray());
    }

    [Fact]
    public async Task Relay_reports_a_truncated_request()
    {
        var request = BuildRequest(new byte[10_000], 4096);
        var cut = request[..(request.Length - 10)];
        var first = new byte[8192];
        Array.Copy(cut, first, ClamdInstreamFramer.HeaderLength);
        var inbound = new TrickleStream(cut[ClamdInstreamFramer.HeaderLength..], 1000);

        var ok = await ClamdInstreamFramer.ForwardRequestAsync(inbound, Stream.Null, first, ClamdInstreamFramer.HeaderLength, CancellationToken.None);

        Assert.False(ok);
    }

    [Fact]
    public async Task Client_streams_the_content_and_reads_the_verdict()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var content = Enumerable.Range(0, 150_000).Select(i => (byte)(i * 7)).ToArray();

        var server = Task.Run(async () =>
        {
            using var tcp = await listener.AcceptTcpClientAsync();
            await using var stream = tcp.GetStream();
            var header = new byte[ClamdInstreamFramer.HeaderLength];
            await stream.ReadExactlyAsync(header);
            Assert.Equal("zINSTREAM\0", Encoding.ASCII.GetString(header));

            using var received = new MemoryStream();
            var len = new byte[4];
            while (true)
            {
                await stream.ReadExactlyAsync(len);
                var n = BinaryPrimitives.ReadUInt32BigEndian(len);
                if (n == 0)
                    break;
                Assert.True(n <= ClamdClient.InstreamChunkSize);
                var chunk = new byte[n];
                await stream.ReadExactlyAsync(chunk);
                received.Write(chunk);
            }

            Assert.Equal(content, received.ToArray());
            await stream.WriteAsync("stream: Eicar-Test-Signature FOUND\0"u8.ToArray());
        });

        using var client = new ClamdClient("127.0.0.1", port);
        using var source = new MemoryStream(content);
        var response = await client.InstreamAsync(source, ClamdEngine.MaxInstreamBytes);
        await server;
        listener.Stop();

        Assert.True(response.Completed);
        Assert.Equal("stream: Eicar-Test-Signature FOUND", response.Text);
    }

    [Fact]
    public async Task Client_refuses_content_above_the_limit()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = listener.AcceptTcpClientAsync();

        using var client = new ClamdClient("127.0.0.1", port);
        using var source = new MemoryStream(new byte[200_000]);
        await Assert.ThrowsAsync<ClamdStreamTooLargeException>(() => client.InstreamAsync(source, 100_000));

        (await accept).Dispose();
        listener.Stop();
    }

    [Fact]
    public void Response_FOUND_becomes_a_threat_on_the_real_path()
    {
        var path = Path.Combine(Path.GetTempPath(), "optiscan_ut_found_" + Guid.NewGuid().ToString("N") + ".exe");
        var result = new ScanResult { Type = ScanType.File, TargetPath = path };

        ClamdEngine.ApplyInstreamResponse(
            new ClamdCommandResult("stream: Win.Test.EICAR_HDB-1 FOUND", true),
            path,
            result,
            progress: null,
            exclusions: new FixedExclusions());

        Assert.Equal(ScanStatus.Completed, result.Status);
        var threat = Assert.Single(result.Threats);
        Assert.Equal(path, threat.FilePath);
        Assert.Equal("Win.Test.EICAR_HDB-1", threat.VirusName);
        Assert.Empty(result.UnscannedFiles);
    }

    [Fact]
    public void Response_OK_counts_one_clean_file()
    {
        var result = new ScanResult();

        ClamdEngine.ApplyInstreamResponse(new ClamdCommandResult("stream: OK", true), @"C:\a.txt", result, null, new FixedExclusions());

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(1, result.FilesScanned);
        Assert.Empty(result.Threats);
    }

    [Theory]
    [InlineData("INSTREAM size limit exceeded. ERROR", true)]
    [InlineData("stream: Can't allocate memory ERROR", true)]
    [InlineData("stream: OK", false)]
    [InlineData("", true)]
    public void Errors_and_incomplete_replies_leave_the_file_unscanned(string text, bool completed)
    {
        var result = new ScanResult();

        ClamdEngine.ApplyInstreamResponse(new ClamdCommandResult(text, completed), @"C:\a.txt", result, null, new FixedExclusions());

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(@"C:\a.txt", Assert.Single(result.UnscannedFiles));
    }

    private sealed class FixedExclusions : IExclusionSettingsAccessor
    {
        public ExclusionSettings Current { get; } = new();
    }

    /// <summary>Flux qui ne rend que quelques octets par lecture, comme un tube ou un socket.</summary>
    private sealed class TrickleStream : Stream
    {
        private readonly byte[] _data;
        private readonly int _step;
        private int _position;

        public TrickleStream(byte[] data, int step)
        {
            _data = data;
            _step = step;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _data.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = Math.Min(Math.Min(count, _step), _data.Length - _position);
            Array.Copy(_data, _position, buffer, offset, n);
            _position += n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
