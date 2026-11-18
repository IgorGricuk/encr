namespace UsbGuard.Core.Crypto;

/// <summary>
/// On-media format of an encrypted file ("*.usbguard.enc"):
///
///  offset size  field
///  ------ ----  -------------------------------------------------
///   0      4    magic  "USBG"
///   4      1    format version (currently 1)
///   5      1    flags (bit0 = filename preserved in manifest only)
///   6      2    reserved (zero)
///   8     16    file id (GUID, big-endian bytes)
///  24     12    per-file base nonce; chunk i uses base || BE32(i) XOR into last 4 bytes
///  36      4    chunk size LE (plaintext bytes per chunk)
///  40      8    plaintext length LE
///  48      .    chunks: each [4-byte LE ciphertext length][ciphertext+GCM tag]
///
/// Every chunk is independently AES-256-GCM sealed with a per-file key derived
/// via HKDF-SHA256(masterKey, info = "usbguard/file/" + fileId). This allows
/// streaming encryption/decryption with bounded memory and corruption of one
/// chunk not destroying the whole file.
/// </summary>
public static class EncFormat
{
    public const uint Magic = 0x47425355; // "USBG" little-endian
    public const byte Version = 1;
    public const int HeaderSize = 48;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;
    public const int DefaultChunkSize = 1 << 20; // 1 MiB

    public static readonly Guid NilId = Guid.Empty;
}

public sealed class EncHeader
{
    public required Guid FileId { get; init; }
    public required byte[] BaseNonce { get; init; }   // 8 bytes; full nonce = base || BE32(chunkIdx)
    public required int ChunkSize { get; init; }
    public required long PlainLength { get; init; }
    public byte Version { get; init; } = EncFormat.Version;
    public byte Flags { get; init; }
}
