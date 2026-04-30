using System.IO;

namespace Vault42.AspNetCore.Internal;

/// <summary>
/// Wraps a stream and throws <see cref="InvalidDataException"/> if the consumer reads
/// more than <see cref="_maxBytes"/> bytes. Used to bound the size of remotely-fetched
/// JSON bodies (e.g. JWKS) so a hostile endpoint cannot exhaust memory.
/// </summary>
internal sealed class LimitedReadStream : Stream
{
    private readonly Stream _inner;
    private readonly long _maxBytes;
    private long _bytesRead;

    internal LimitedReadStream(Stream inner, long maxBytes)
    {
        _inner = inner;
        _maxBytes = maxBytes;
    }

    public override bool CanRead => _inner.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _bytesRead;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var n = _inner.Read(buffer, offset, count);
        TrackAndCheck(n);
        return n;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var n = await _inner.ReadAsync(buffer, cancellationToken);
        TrackAndCheck(n);
        return n;
    }

    private void TrackAndCheck(int n)
    {
        _bytesRead += n;
        if (_bytesRead > _maxBytes)
        {
            throw new InvalidDataException(
                $"Stream exceeded maximum allowed size of {_maxBytes} bytes");
        }
    }

    public override void Flush() => _inner.Flush();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}
