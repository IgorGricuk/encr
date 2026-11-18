using System.Buffers.Binary;
using System.Security.Cryptography;

namespace UsbGuard.Core.Crypto;

/// <summary>
/// Streaming AES-256-GCM encryptor producing the USBG ".enc" container.
/// Memory usage is O(chunkSize) regardless of file size.
/// </summary>
public sealed class EncFileWriter : IDisposable
{
    private readonly Stream _out;
    private readonly _Aead _aes;
    private readonly byte[] _plainBuf;
    private readonly byte[] _cipherBuf;
    private readonly byte[] _lenBuf = new byte[4];
    private readonly byte[] _nonce = new byte[EncFormat.NonceSize];
    private readonly Guid _fileId;
    private readonly byte[] _baseNonce;
    private long _position;
    private int _chunkIndex;
    private bool _finished;

    public EncFileWriter(Stream output, ReadOnlySpan<byte> masterKey, Guid fileId,
                         byte[] baseNonce, int chunkSize = EncFormat.DefaultChunkSize)
    {
        if (masterKey.Length != EncFormat.KeySize)
            throw new ArgumentException("master key must be 32 bytes", nameof(masterKey));
        if (baseNonce.Length != 8)
            throw new ArgumentException("base nonce must be 8 bytes", nameof(baseNonce));

        _out = output;
        _fileId = fileId;
        _baseNonce = baseNonce;
        _aes = new _Aead(DeriveFileKey(masterKey, fileId));
        _plainBuf = new byte[chunkSize];
        _cipherBuf = new byte[chunkSize + EncFormat.TagSize];

        WriteHeader(chunkSize);
    }

    /// <summary>Per-file key = HKDF-SHA256(master, salt=0, info="usbguard/file/{guid:N}").</summary>
    public static byte[] DeriveFileKey(ReadOnlySpan<byte> masterKey, Guid fileId)
    {
        Span<byte> info = stackalloc byte[40]; // "usbguard/file/" + 32 hex chars
        System.Text.Encoding.UTF8.TryGetBytes($"usbguard/file/{fileId:N}", info, out _);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey.ToArray(), EncFormat.KeySize,
                              salt: null, info: info.ToArray());
    }

    private void WriteHeader(int chunkSize)
    {
        Span<byte> header = stackalloc byte[EncFormat.HeaderSize];
        BinaryPrimitives.WriteUInt32LittleEndian(header[..4], EncFormat.Magic);
        header[4] = EncFormat.Version;
        header[5] = 0;              // flags
        header.Slice(6, 2).Clear(); // reserved
        fileIdToBytes(_fileId, header.Slice(8, 16));
        _baseNonce.CopyTo(header.Slice(24, 8));
        header.Slice(32, 4).Clear(); // nonce tail filled per-chunk conceptually; stored zero
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(36, 4), chunkSize);
        BinaryPrimitives.WriteInt64LittleEndian(header.Slice(40, 8), 0); // patched on Finish
        _out.Write(header);
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_finished, this);
        while (!data.IsEmpty)
        {
            int fill = (int)(_buffered % _plainBuf.Length);
            int free = _plainBuf.Length - fill;
            int take = Math.Min(free, data.Length);
            data[..take].CopyTo(_plainBuf.AsSpan(fill));
            _buffered += take;
            _position += take;
            data = data[take..];
            if (_buffered == _plainBuf.Length)
            {
                FlushChunk(_plainBuf.Length);
                _buffered = 0;
            }
        }
    }

    private long _buffered; // bytes currently held in _plainBuf (0..chunkSize)

    private void FlushChunk(int used)
    {
        MakeNonce(_chunkIndex);
        int ctLen = _aes.Seal(_nonce, _plainBuf.AsSpan(0, used),
                              _cipherBuf.AsSpan(0, used + EncFormat.TagSize));
        BinaryPrimitives.WriteInt32LittleEndian(_lenBuf, ctLen);
        _out.Write(_lenBuf);
        _out.Write(_cipherBuf.AsSpan(0, ctLen));
        _chunkIndex++;
    }

    private void MakeNonce(int chunkIdx)
    {
        _baseNonce.CopyTo(_nonce, 0);
        BinaryPrimitives.WriteInt32BigEndian(_nonce.AsSpan(8, 4), chunkIdx);
    }

    public void Finish()
    {
        if (_finished) return;
        if (_buffered > 0 || _position == 0)
            FlushChunk((int)_buffered);
        // patch plaintext length at offset 40
        if (_out.CanSeek)
        {
            long end = _out.Position;
            _out.Seek(40, SeekOrigin.Begin);
            Span<byte> len = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(len, _position);
            _out.Write(len);
            _out.Seek(end, SeekOrigin.Begin);
        }
        _out.Flush();
        _finished = true;
    }

    private static void fileIdToBytes(Guid id, Span<byte> dest) =>
        id.ToByteArray().CopyTo(dest); // note: stores raw GUID byte layout

    public void Dispose() => _aes.Dispose();
}
