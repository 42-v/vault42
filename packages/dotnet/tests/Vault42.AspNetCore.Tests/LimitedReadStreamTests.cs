using System.IO;
using System.Text;
using Vault42.AspNetCore.Internal;
using Xunit;

namespace Vault42.AspNetCore.Tests;

/// <summary>
/// LimitedReadStream is the only thing standing between a hostile JWKS endpoint
/// and the process heap: VaultJwksManager wraps the response body in it before
/// handing the body to the JSON reader, so a server that answers the fetch with
/// an endless stream is cut off at MaxJwksBytes rather than read to completion.
/// It shipped in 1.0.0 with no test of its own.
///
/// The property that matters is that the budget is cumulative. A per-read check
/// would pass every one of these tests except
/// <see cref="ManyReads_ExceedTheBudgetInAggregate_Throws"/>, and would let an
/// endpoint stream unbounded data as long as no single read was large.
/// </summary>
public class LimitedReadStreamTests
{
    [Fact]
    public void ReadUnderTheLimit_Succeeds()
    {
        using var stream = Wrap("hello", maxBytes: 1024);
        var buffer = new byte[16];

        var n = stream.Read(buffer, 0, buffer.Length);

        Assert.Equal(5, n);
        Assert.Equal("hello", Encoding.UTF8.GetString(buffer, 0, n));
    }

    // The limit is a maximum, not a strict bound: a body of exactly MaxJwksBytes
    // is the largest legitimate one and must not be refused.
    [Fact]
    public void ReadExactlyTheLimit_Succeeds()
    {
        using var stream = Wrap(new string('x', 64), maxBytes: 64);
        var buffer = new byte[64];

        var n = stream.Read(buffer, 0, buffer.Length);

        Assert.Equal(64, n);
    }

    [Fact]
    public void ReadOneByteOverTheLimit_Throws()
    {
        using var stream = Wrap(new string('x', 65), maxBytes: 64);
        var buffer = new byte[128];

        var ex = Assert.Throws<InvalidDataException>(() => stream.Read(buffer, 0, buffer.Length));
        Assert.Contains("64", ex.Message, StringComparison.Ordinal);
    }

    // The async overload is the one VaultJwksManager actually reaches through
    // JsonSerializer.DeserializeAsync. A limit enforced only on the synchronous
    // path would be enforced on no path that ships.
    [Fact]
    public async Task ReadAsyncOverTheLimit_Throws()
    {
        await using var stream = Wrap(new string('x', 65), maxBytes: 64);
        var buffer = new byte[128];

        await Assert.ThrowsAsync<InvalidDataException>(
            async () => _ = await stream.ReadAsync(buffer.AsMemory()));
    }

    // The check is on the running total, not on the size of one read.
    [Fact]
    public void ManyReads_ExceedTheBudgetInAggregate_Throws()
    {
        using var stream = Wrap(new string('x', 100), maxBytes: 10);
        var buffer = new byte[4];

        Assert.Equal(4, stream.Read(buffer, 0, 4));
        Assert.Equal(4, stream.Read(buffer, 0, 4));
        Assert.Throws<InvalidDataException>(() => stream.Read(buffer, 0, 4));
    }

    [Fact]
    public void Position_ReportsBytesReadSoFar()
    {
        using var stream = Wrap("0123456789", maxBytes: 1024);
        var buffer = new byte[4];

        Assert.Equal(0, stream.Position);
        Assert.Equal(4, stream.Read(buffer, 0, 4));
        Assert.Equal(4, stream.Position);
        Assert.Equal(4, stream.Read(buffer, 0, 4));
        Assert.Equal(8, stream.Position);
    }

    // Everything but forward reading is refused. A stream that silently accepted
    // a Seek would let a consumer rewind past the counter and read the budget
    // twice; one that accepted a Write would make the wrapper a write path onto
    // a response body.
    [Fact]
    public void SeekingAndWritingAreRefused()
    {
        using var stream = Wrap("payload", maxBytes: 1024);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(10));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
    }

    // The wrapper owns the response body it was handed. Leaving the inner stream
    // open would leak the connection for every JWKS refresh, one per interval,
    // for the lifetime of the process.
    [Fact]
    public void Dispose_DisposesTheInnerStream()
    {
        var inner = new TrackingStream(Encoding.UTF8.GetBytes("payload"));
        var stream = new LimitedReadStream(inner, 1024);

        stream.Dispose();

        Assert.True(inner.Disposed);
    }

    [Fact]
    public void Flush_ReachesTheInnerStream()
    {
        var inner = new TrackingStream(Encoding.UTF8.GetBytes("payload"));
        using var stream = new LimitedReadStream(inner, 1024);

        stream.Flush();

        Assert.True(inner.Flushed);
    }

    private static LimitedReadStream Wrap(string body, long maxBytes) =>
        new (new MemoryStream(Encoding.UTF8.GetBytes(body)), maxBytes);

    private sealed class TrackingStream : MemoryStream
    {
        internal TrackingStream(byte[] buffer)
            : base(buffer)
        {
        }

        internal bool Disposed { get; private set; }

        internal bool Flushed { get; private set; }

        public override void Flush()
        {
            Flushed = true;
            base.Flush();
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
