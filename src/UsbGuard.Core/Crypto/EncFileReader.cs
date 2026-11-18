using System.Buffers.Binary;
using System.Security.Cryptography;

namespace UsbGuard.Core.Crypto;

public sealed class CorruptedEncFileException : Exception
{
    public CorruptedEncFileException(string message) : base(message) { }
    public CorruptedEncFileException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Streaming decryptor for the USBG ".enc" container. Every chunk is verified
/// with AES-256-GCM; a foreign/corrupt file fails fast (magic check + tag).
/// </summary>
public sealed class EncFileReader : IDisposable
{
    private readonly Stream _src;
    private readonly _Aead _aes;
    private readonly EncHeader _header;
    private readonly byte[] _cipherBuf;
    private readonly byte[] _plainBuf;
    private readonly byte[] _lenBuf = new byte[4];
    private readonly byte[] _nonce = new byte[EncFormat.NonceSize];
    private long _remaining;
    private int _chunkIndex;

    private EncFileReader(Stream src, EncHeader header, _Aead aes)
    {
        _src = src;
        _header = header;
        _aes = aes;
        _cipherBuf = new byte[header.ChunkSize + EncFormat.TagSize];
        _plainBuf = new byte[header.ChunkSize];
        _remaining = header.PlainLength;
    }

    /// <summary>Parses and validates the header. Throws on bad magic/version.</summary>
    public static EncHeader ReadHeader(Stream src)
    {
        Span<byte> h = stackalloc byte[EncFormat.HeaderSize];
        ReadExactOrThrow(src, h, "file too short to contain a USBG header");
        if (BinaryPrimitives.ReadUInt32LittleEndian(h[..4]) != EncFormat.Magic)
            throw new CorruptedEncFileException("not a USBG .enc file (bad magic)");
        byte version = h[4];
        if (version != EncFormat.Version)
            throw new CorruptedEncFileException($"unsupported USBG format version {version}");

        var idBytes = h.Slice(8, 16).ToArray();
        return new EncHeader
        {
            Version = version,
            Flags = h[5],
            FileId = new Guid(idBytes),
            BaseNonce = h.Slice(24, 8).ToArray(),
            ChunkSize = BinaryPrimitives.ReadInt32LittleEndian(h.Slice(36, 4)),
            PlainLength = BinaryPrimitives.ReadInt64LittleEndian(h.Slice(40, 8)),
        };
    }

    public static bool IsEncFile(Stream src)
    {
        if (!src.CanSeek) return false;
        long pos = src.Position;
        try
        {
            Span<byte> magic = stackalloc byte[4];
            if (src.Read(magic) < 4) return false;
            return BinaryPrimitives.ReadUInt32LittleEndian(magic) == EncFormat.Magic;
        }
        finally { src.Seek(pos, SeekOrigin.Begin); }
    }

    public static EncFileReader Open(Stream source, ReadOnlySpan<byte> masterKey)
    {
        var header = ReadHeader(source);
        if (header.ChunkSize <= 0 || header.ChunkSize > (1 << 26))
            throw new CorruptedEncFileException($"implausible chunk size {header.ChunkSize}");
        if (header.PlainLength < 0)
            throw new CorruptedEncFileException("negative plaintext length");
        var aes = new _Aead(EncFileWriter.DeriveFileKey(masterKey, header.FileId));
        return new EncFileReader(source, header, aes);
    }

    public EncHeader Header => _header;

    /// <summary>Returns up to dest.Length decrypted bytes; 0 at EOF. Throws on auth failure.</summary>
    public int Read(Span<byte> dest)
    {
        if (_remaining == 0) return 0;
        // current chunk plaintext size
        int chunkPlain = (int)Math.Min(_header.ChunkSize, _remaining);
        if (_bufferedCount == 0)
        {
            FillChunkBuffer();
        }
        int take = Math.Min(chunkPlain, Math.Min(dest.Length, _bufferedCount - _bufferedPos));
        _plainBuf.AsSpan(_bufferedPos, take).CopyTo(dest);
        _bufferedPos += take;
        _remaining -= take;
        if (_bufferedPos == _bufferedCount) { _bufferedPos = 0; _bufferedCount = 0; }
        return take;
    }

    private int _bufferedCount, _bufferedPos;

    private void FillChunkBuffer()
    {
        MakeNonce(_chunkIndex);
        ReadExactOrThrow(_src, _lenBuf, "truncated .enc: missing chunk length");
        int ctLen = BinaryPrimitives.ReadInt32LittleEndian(_lenBuf);
        if (ctLen <= 0 || ctLen > _cipherBuf.Length)
            throw new CorruptedEncFileException($"bad chunk length {ctLen}");
        ReadExactOrThrow(_src, _cipherBuf.AsSpan(0, ctLen), "truncated .enc: missing chunk data");
        _bufferedCount = _aes.Open(_nonce, _cipherBuf.AsSpan(0, ctLen), _plainBuf);
        _bufferedPos = 0;
        _chunkIndex++;
    }

    private void MakeNonce(int chunkIdx)
    {
        _header.BaseNonce.CopyTo(_nonce, 0);
        BinaryPrimitives.WriteInt32BigEndian(_nonce.AsSpan(8, 4), chunkIdx);
    }

    internal static void ReadExactOrThrow(Stream s, Span<byte> dest, string error)
    {
        int read = 0;
        while (read < dest.Length)
        {
            int n = s.Read(dest[read..]);
            if (n == 0) throw new CorruptedEncFileException(error);
            read += n;
        }
    }

    public void Dispose() => _aes.Dispose();
}
