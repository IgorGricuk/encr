using System.Security.Cryptography;

namespace UsbGuard.Core.Crypto;

/// <summary>
/// High-level one-shot operations used by the agent and CLI.
/// All work is streaming; RAM usage bounded by chunk size.
/// </summary>
public static class CryptoEngine
{
    /// <summary>Encrypts plaintext stream into an .enc container stream.</summary>
    public static void Encrypt(Stream plaintext, Stream ciphertext,
                               ReadOnlySpan<byte> masterKey, Guid fileId,
                               int chunkSize = EncFormat.DefaultChunkSize)
    {
        var baseNonce = RandomNumberGenerator.GetBytes(8);
        using var writer = new EncFileWriter(ciphertext, masterKey, fileId, baseNonce, chunkSize);
        CopyWithProgress(plaintext, writer, chunkSize);
        writer.Finish();
    }

    /// <summary>Decrypts an .enc container into plaintext stream.</summary>
    public static void Decrypt(Stream ciphertext, Stream plaintext, ReadOnlySpan<byte> masterKey)
    {
        using var reader = EncFileReader.Open(ciphertext, masterKey);
        var buf = new byte[Math.Max(reader.Header.ChunkSize, 64 * 1024)];
        int n;
        while ((n = reader.Read(buf)) > 0)
            plaintext.Write(buf, 0, n);
    }

    /// <summary>Reads header without decrypting (for tooling / status).</summary>
    public static EncHeader PeekHeader(Stream ciphertext) => EncFileReader.ReadHeader(ciphertext);

    private static void CopyWithProgress(Stream src, EncFileWriter dst, int chunkSize)
    {
        var buf = new byte[chunkSize];
        int n;
        while ((n = src.Read(buf)) > 0)
            dst.Write(buf.AsSpan(0, n));
    }
}
