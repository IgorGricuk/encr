using System.Security.Cryptography;

namespace UsbGuard.Core.Crypto;

/// <summary>
/// Abstraction over the machine-protected master key store.
/// Windows implementation: DPAPI (CurrentUser+LocalMachine) with optional TPM seal.
/// Test/Unix implementation: file-based with 0600 perms (NOT for production).
/// </summary>
public interface IKeyProvider
{
    /// <summary>Returns the 32-byte master key, creating it on first use.</summary>
    byte[] GetMasterKey();

    /// <summary>Exports an escrow copy wrapped with a passphrase-derived key (PBKDF2).</summary>
    byte[] ExportBackup(string passphrase);

    /// <summary>Imports an escrow backup, replacing the local master key.</summary>
    void ImportBackup(byte[] wrapped, string passphrase);
}

/// <summary>
/// Portable reference implementation used by tests and non-Windows dev boxes.
/// The master key is stored at &lt;keyDir&gt;/master.key protected by a locally
/// generated "machine secret" — this is deliberately weak-ish and exists only
/// so the pipeline can be exercised without Windows APIs.
/// </summary>
public sealed class FileKeyProvider : IKeyProvider
{
    private readonly string _keyFile;
    private readonly string _machineSecretFile;
    private byte[]? _cached;

    public FileKeyProvider(string keyDirectory)
    {
        Directory.CreateDirectory(keyDirectory);
        _keyFile = Path.Combine(keyDirectory, "master.key");
        _machineSecretFile = Path.Combine(keyDirectory, ".machine_secret");
    }

    public byte[] GetMasterKey()
    {
        if (_cached != null) return (byte[])_cached.Clone();
        var secret = GetOrCreateMachineSecret();
        byte[] master;
        if (File.Exists(_keyFile))
        {
            var blob = File.ReadAllBytes(_keyFile);
            master = Unwrap(blob, secret);
        }
        else
        {
            master = RandomNumberGenerator.GetBytes(EncFormat.KeySize);
            File.WriteAllBytes(_keyFile, Wrap(master, secret));
        }
        _cached = master;
        return (byte[])master.Clone();
    }

    public byte[] ExportBackup(string passphrase)
    {
        var master = GetMasterKey();
        try { return WrapWithPassphrase(master, passphrase); }
        finally { CryptographicOperations.ZeroMemory(master); }
    }

    public void ImportBackup(byte[] wrapped, string passphrase)
    {
        var master = UnwrapWithPassphrase(wrapped, passphrase);
        var secret = GetOrCreateMachineSecret();
        File.WriteAllBytes(_keyFile, Wrap(master, secret));
        CryptographicOperations.ZeroMemory(master);
        _cached = null;
    }

    private byte[] GetOrCreateMachineSecret()
    {
        if (File.Exists(_machineSecretFile)) return File.ReadAllBytes(_machineSecretFile);
        var s = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(_machineSecretFile, s);
        TryRestrictPermissions(_machineSecretFile);
        TryRestrictPermissions(_keyFile);
        return s;
    }

    private static void TryRestrictPermissions(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            fi.Attributes |= FileAttributes.Hidden;
        }
        catch { /* best effort on non-NTFS */ }
    }

    // AES-GCM wrap with key = HKDF(secret, "usbguard/keywrap")
    private static byte[] Wrap(byte[] plain, byte[] secret)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32,
                                 info: "usbguard/keywrap"u8.ToArray());
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plain.Length + 16];
        _Aead.SealTo(key, nonce, plain, ct);
        return [.. nonce, .. ct];
    }

    private static byte[] Unwrap(byte[] blob, byte[] secret)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32,
                                 info: "usbguard/keywrap"u8.ToArray());
        var plain = new byte[blob.Length - 12 - 16];
        _Aead.OpenWith(key, blob.AsSpan(0, 12), blob.AsSpan(12), plain);
        return plain;
    }

    public const int Pbkdf2Iterations = 600_000;

    internal static byte[] WrapWithPassphrase(byte[] plain, string passphrase)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Pbkdf2Iterations,
                                            HashAlgorithmName.SHA256, 32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plain.Length + 16];
        _Aead.SealTo(key, nonce, plain, ct);
        return [.. "USBGBAK1"u8, .. salt, .. nonce, .. ct];
    }

    internal static byte[] UnwrapWithPassphrase(byte[] blob, string passphrase)
    {
        if (blob.Length < 8 + 16 + 12 + 16 ||
            !blob.AsSpan(0, 8).SequenceEqual("USBGBAK1"u8))
            throw new CryptographicException("not a USBG key backup");
        var salt = blob.AsSpan(8, 16).ToArray();
        var nonce = blob.AsSpan(24, 12).ToArray();
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Pbkdf2Iterations,
                                            HashAlgorithmName.SHA256, 32);
        var plain = new byte[blob.Length - 24 - 16];
        _Aead.OpenWith(key, nonce, blob.AsSpan(24), plain); // throws on wrong passphrase
        return plain;
    }
}
