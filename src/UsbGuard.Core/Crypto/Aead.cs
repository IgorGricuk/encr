using System.Buffers.Binary;
using System.Security.Cryptography;
using ITransform = System.Security.Cryptography.ICryptoTransform;

namespace UsbGuard.Core.Crypto;

/// <summary>
/// Minimal AES-256-GCM AEAD built on <see cref="Aes"/> + manual CTR-mode GHASH-less
/// construction is NOT used here — instead we implement GCM via BCL primitives:
///   * counter mode encryption with Aes (EncryptEcb on keystream blocks)
///   * authentication with a pure GHASH over GF(2^128)
/// This keeps the project dependency-free and works on every .NET 8 platform,
/// including runtimes where the AesGcm type lacks hardware-accelerated Seal/Open.
/// Output layout matches standard AES-GCM: ciphertext || tag(16).
/// </summary>
internal sealed class _Aead : IDisposable
{
    private readonly byte[] _h;      // GHASH subkey H = E(K, 0^128)
    private readonly Aes _aes;
    private readonly byte[] _ecbBuf = new byte[16];

    public _Aead(byte[] key32)
    {
        _aes = Aes.Create();
        _aes.KeySize = 256;
        _aes.Key = key32;
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        using var ecb = _aes.CreateEncryptor();
        _h = TransformBlock(ecb, new byte[16]);
    }

    private static byte[] TransformBlock(ITransform t, byte[] block) => t.TransformFinalBlock(block, 0, 16);

    private byte[] KeystreamBlock(Span<byte> counter)
    {
        using var ecb = _aes.CreateEncryptor();
        return TransformBlock(ecb, counter.ToArray());
    }

    public int Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        var ct = ciphertextWithTag[..plaintext.Length];
        var tag = ciphertextWithTag[plaintext.Length..(plaintext.Length + 16)];
        Crypt(nonce, plaintext, ct, tag);
        return ciphertextWithTag.Length >= plaintext.Length + 16 ? plaintext.Length + 16 : 0;
    }

    public int Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextWithTage, Span<byte> plaintext)
    {
        if (ciphertextWithTage.Length < 16)
            throw new CryptographicException("ciphertext too short");
        var ct = ciphertextWithTage[..^16];
        var tag = ciphertextWithTage[^16..];
        var expected = new byte[16];
        Crypt(nonce, default, ct.ToArray(), expected, decrypt: true, providedPlain: plaintext);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            throw new CryptographicException("GCM tag mismatch (wrong key or tampered data)");
        return ct.Length;
    }

    /// <summary>Core CTR+GHASH. For encryption writes plain→ct+tag; for decryption reads ct→plain+tag.</summary>
    private void Crypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
                       Span<byte> ctOut, Span<byte> tagOut, bool decrypt = false,
                       Span<byte> providedPlain = default)
    {
        // J0 = nonce || 0^31 || 1   (96-bit nonce assumed)
        var j0 = new byte[16];
        nonce.CopyTo(j0);
        j0[15] = 1;

        Span<byte> aad = stackalloc byte[0];
        long len = decrypt ? ctOut.Length : plaintext.Length;

        var gh = new Ghash(_h);
        gh.UpdatePadded(aad);

        var counter = (byte[])j0.Clone();
        var src = decrypt ? ctOut : plaintext;
        var dst = decrypt ? providedPlain : ctOut;

        long done = 0;
        while (done < len)
        {
            IncrementCounter(counter);
            var ks = KeystreamBlock(counter);
            int n = (int)Math.Min(16, len - done);
            for (int i = 0; i < n; i++)
                dst[(int)done + i] = (byte)(src[(int)done + i] ^ ks[i]);
            gh.UpdatePadded(dst.Slice((int)done, n)); // GHASH over ciphertext
            done += n;
        }

        // GHASH final block: len(A)||len(C) in bits
        Span<byte> lens = stackalloc byte[16];
        BinaryPrimitives.WriteInt64BigEndian(lens[..8], (long)aad.Length * 8);
        BinaryPrimitives.WriteInt64BigEndian(lens[8..], len * 8);
        gh.UpdateRaw(lens);

        var s = gh.Finish();
        var encJ0 = KeystreamBlock(j0);
        for (int i = 0; i < 16; i++) tagOut[i] = (byte)(s[i] ^ encJ0[i]);
    }

    private static void IncrementCounter(byte[] c)
    {
        for (int i = 15; i >= 12; i--)
            if (++c[i] != 0) break;
    }

    public void Dispose() => _aes.Dispose();

    /// <summary>One-shot helpers for callers without a long-lived instance.</summary>
    public static void SealTo(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plain, Span<byte> ctTag)
    {
        using var a = new _Aead(key);
        a.Seal(nonce, plain, ctTag);
    }

    public static int OpenWith(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ctTag, Span<byte> plain)
    {
        using var a = new _Aead(key);
        return a.Open(nonce, ctTag, plain);
    }
}

/// <summary>GF(2^128) multiplier per NIST SP 800-38D (right-shift, R = 0xE1…).</summary>
internal sealed class Ghash
{
    private static readonly byte[] R = [0xE1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    private readonly byte[] _h;
    private readonly byte[] _y = new byte[16];

    public Ghash(byte[] h) => _h = h;

    public void UpdatePadded(ReadOnlySpan<byte> data)
    {
        int full = data.Length / 16;
        for (int b = 0; b < full; b++) MultiplyXor(data.Slice(b * 16, 16));
        int rem = data.Length % 16;
        if (rem != 0)
        {
            Span<byte> block = stackalloc byte[16];
            data[^rem..].CopyTo(block);
            MultiplyXor(block);
        }
    }

    public void UpdateRaw(ReadOnlySpan<byte> block16) => MultiplyXor(block16);

    private void MultiplyXor(ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < 16; i++) _y[i] ^= block[i];
        // Y = Y · H in GF(2^128)
        var z = new byte[16];
        var v = (byte[])_y.Clone();
        for (int i = 0; i < 128; i++)
        {
            if (((_h[i / 8] >> (7 - i % 8)) & 1) == 1)
                for (int j = 0; j < 16; j++) z[j] ^= v[j];
            bool lsb = (v[15] & 1) == 1;
            ShiftRight1(v);
            if (lsb) for (int j = 0; j < 16; j++) v[j] ^= R[j];
        }
        Array.Copy(z, _y, 16);
    }

    private static void ShiftRight1(byte[] b)
    {
        for (int i = 15; i > 0; i--)
            b[i] = (byte)((b[i] >> 1) | (b[i - 1] << 7));
        b[0] >>= 1;
    }

    public byte[] Finish() => _y;
}
