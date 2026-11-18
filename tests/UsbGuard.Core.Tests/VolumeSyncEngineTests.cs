using System.Security.Cryptography;
using System.Text;
using UsbGuard.Core.Crypto;
using UsbGuard.Core.Storage;
using UsbGuard.Core.Sync;
using Xunit;

namespace UsbGuard.Core.Tests;

public class VolumeSyncEngineTests : IDisposable
{
    private readonly string _root = MakeTempDir();
    private readonly string _keyDir = MakeTempDir();
    private readonly FileKeyProvider _keys;
    private readonly VolumeSyncEngine _engine;

    public VolumeSyncEngineTests()
    {
        _keys = new FileKeyProvider(_keyDir);
        _engine = new VolumeSyncEngine(_keys, new SyncOptions());
    }

    private static string MakeTempDir()
    {
        var p = Path.Combine(Path.GetTempPath(), "usbguard-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        return p;
    }

    private string Write(string rel, byte[] content)
    {
        var full = Path.Combine(_root, rel.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
        // make mtime clearly older than the 1s freshness guard
        File.SetLastWriteTimeUtc(full, DateTime.UtcNow.AddSeconds(-30));
        return full;
    }

    [Fact]
    public void Plaintext_Files_Become_Encrypted_And_Originals_Gone()
    {
        Write("docs/report.txt", Encoding.UTF8.GetBytes("quarterly numbers"));
        Write("photo.jpg", RandomNumberGenerator.GetBytes(5000));

        var report = _engine.SynchronizeOnce(_root);
        Assert.Equal(2, report.Encrypted);
        Assert.Equal(0, report.Errors);

        Assert.False(File.Exists(Path.Combine(_root, "docs/report.txt")));
        Assert.True(File.Exists(Path.Combine(_root, "docs/report.txt.usbguard.enc")));
        Assert.True(File.Exists(MediaPaths.ManifestPath(_root)));

        // decrypt back through manifest entry
        var manifest = new ManifestStore(_root).Load();
        var entry = manifest.ByPath["docs/report.txt"];
        using var src = File.OpenRead(Path.Combine(_root, "docs/report.txt.usbguard.enc"));
        using var dst = new MemoryStream();
        CryptoEngine.Decrypt(src, dst, _keys.GetMasterKey());
        Assert.Equal("quarterly numbers", Encoding.UTF8.GetString(dst.ToArray()));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("quarterly numbers")))
                     .ToLowerInvariant(), entry.Sha256Hex);
    }

    [Fact]
    public void Second_Pass_Is_Noop_For_Unchanged_Files()
    {
        Write("a.bin", new byte[100]);
        Assert.Equal(1, _engine.SynchronizeOnce(_root).Encrypted);
        Assert.Equal(0, _engine.SynchronizeOnce(_root).Encrypted);
    }

    [Fact]
    public void File_Dropped_From_Untrusted_Pc_Is_Encrypted_On_Return()
    {
        // simulate: user took the stick to a PC without the agent and copied a file on it
        Write("new-from-other-pc.docx", Encoding.UTF8.GetBytes("injected document"));
        var r = _engine.SynchronizeOnce(_root);
        Assert.Equal(1, r.Encrypted);
        Assert.False(File.Exists(Path.Combine(_root, "new-from-other-pc.docx")));
        Assert.True(File.Exists(Path.Combine(_root, "new-from-other-pc.docx.usbguard.enc")));
    }

    [Fact]
    public void Modified_Encrypted_Pair_Reencrypted_When_Plaintext_Restored()
    {
        Write("notes.txt", Encoding.UTF8.GetBytes("v1"));
        _engine.SynchronizeOnce(_root);
        // plaintext reappears (restored copy), stale .enc still there
        Write("notes.txt", Encoding.UTF8.GetBytes("v2 edited elsewhere"));
        _engine.SynchronizeOnce(_root);
        Assert.False(File.Exists(Path.Combine(_root, "notes.txt")));
        using var src = File.OpenRead(Path.Combine(_root, "notes.txt.usbguard.enc"));
        using var dst = new MemoryStream();
        CryptoEngine.Decrypt(src, dst, _keys.GetMasterKey());
        Assert.Equal("v2 edited elsewhere", Encoding.UTF8.GetString(dst.ToArray()));
    }

    [Fact]
    public void Excluded_Paths_Are_Untouched()
    {
        Write("$recycle.bin/s-1-5/x.dat", new byte[10]);
        Write(".usbguard/keepme.txt", new byte[10]);
        Write("shortcut.lnk", new byte[10]);
        var r = _engine.SynchronizeOnce(_root);
        Assert.Equal(0, r.Encrypted);
        Assert.True(File.Exists(Path.Combine(_root, "shortcut.lnk")));
    }

    [Fact]
    public void Deleted_Enc_File_Produces_Tombstone()
    {
        Write("gone.txt", new byte[42]);
        _engine.SynchronizeOnce(_root);
        File.Delete(Path.Combine(_root, "gone.txt.usbguard.enc"));
        var r = _engine.SynchronizeOnce(_root);
        Assert.Equal(1, r.Deleted);
        var manifest = new ManifestStore(_root).Load();
        Assert.Equal(FileState.Deleted, manifest.ByPath["gone.txt"].State);
    }

    [Fact]
    public void Manifest_Survives_Corruption_Of_Main_Copy()
    {
        Write("f.txt", Encoding.UTF8.GetBytes("data"));
        _engine.SynchronizeOnce(_root);           // creates manifest.json
        _engine.SynchronizeOnce(_root);           // second save → creates manifest.json.bak
        File.WriteAllText(MediaPaths.ManifestPath(_root), "{ this is not json");
        var manifest = new ManifestStore(_root).Load();
        Assert.Single(manifest.Entries);          // recovered from .bak
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); Directory.Delete(_keyDir, true); } catch { }
    }
}
