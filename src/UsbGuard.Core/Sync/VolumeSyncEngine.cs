using System.Security.Cryptography;
using UsbGuard.Core.Crypto;
using UsbGuard.Core.Storage;

namespace UsbGuard.Core.Sync;

public sealed record SyncOptions
{
    /// <summary>Files smaller than this are still encrypted (no threshold by default).</summary>
    public long MinSizeBytes { get; init; } = 0;

    /// <summary>Relative-path prefixes never touched (case-insensitive, '/' separators).</summary>
    public IReadOnlyList<string> ExcludePrefixes { get; init; } =
        [".usbguard/", "$recycle.bin/", "system volume information/", ".si_", ".trashes/"];

    /// <summary>Extensions skipped entirely (e.g. shortcuts that break when renamed).</summary>
    public IReadOnlySet<string> ExcludeExtensions { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".lnk" };

    /// <summary>Delete plaintext originals after successful encryption (the security-critical default).</summary>
    public bool DeleteOriginals { get; init; } = true;

    /// <summary>Max files processed per pass (fairness across volumes).</summary>
    public int BatchLimit { get; init; } = 512;
}

public sealed record SyncReport(int Encrypted, int Deleted, int Errors, TimeSpan Elapsed)
{
    public List<string> ErrorDetails { get; } = [];
    public override string ToString() =>
        $"encrypted={Encrypted} deleted={Deleted} errors={Errors} in {Elapsed.TotalSeconds:F1}s";
}

/// <summary>
/// Core of the agent: given a mounted volume root, brings the media to a
/// consistent state:
///   * every non-excluded plaintext file          → encrypted (.enc) + original removed
///   * every .enc whose entry is stale/deleted    → manifest cleaned / orphan .enc kept
///   * files modified externally (on untrusted PC)→ re-detected via size/mtime/hash, re-encrypted
/// This realises both directions of the threat model in the task statement.
/// </summary>
public sealed class VolumeSyncEngine(IKeyProvider keys, SyncOptions options)
{
    public SyncOptions Options { get; } = options;

    public SyncReport SynchronizeOnce(string volumeRoot, CancellationToken ct = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var store = new ManifestStore(volumeRoot);
        var manifest = store.Load();
        int enc = 0, del = 0, err = 0;

        var diskFiles = EnumerateCandidateFiles(volumeRoot);

        // ---- Pass 1: encrypt everything plaintext on the media -----------------
        foreach (var file in diskFiles.Plain.Where(_ => !ct.IsCancellationRequested))
        {
            if (enc >= Options.BatchLimit) break;
            try
            {
                if (EncryptOne(volumeRoot, manifest, file, ct)) enc++;
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                err++;
                TrackError(manifest, volumeRoot, file, ex);
            }
        }

        // ---- Pass 2: reconcile manifest vs disk --------------------------------
        foreach (var entry in manifest.Entries.Where(e => e.State == FileState.Encrypted).ToList())
        {
            var encFull = MediaPaths.FromRelative(volumeRoot, entry.EncRelativePath!);
            var plainFull = MediaPaths.FromRelative(volumeRoot, entry.RelativePath);

            if (!File.Exists(encFull))
            {
                // .enc was removed from the media → drop the entry
                entry.State = FileState.Deleted;
                entry.UpdatedAt = DateTimeOffset.UtcNow;
                del++;
                continue;
            }
            if (File.Exists(plainFull))
            {
                // Original reappeared (user copied it back / untrusted PC restored
                // a plaintext version): remove the stale ciphertext; the fresh
                // plaintext will be picked up by the next sync pass.
                TryDeleteStalePair(entry, encFull);
                continue;
            }
        }

        // prune tombstones older than 30 days
        manifest.Entries.RemoveAll(e => e.State == FileState.Deleted &&
                                        e.UpdatedAt < DateTimeOffset.UtcNow.AddDays(-30));
        manifest.Reindex();
        store.Save(manifest);
        return new SyncReport(enc, del, err, sw.Elapsed);
    }

    private (List<string> Plain, List<string> Enc) EnumerateCandidateFiles(string volumeRoot)
    {
        var plain = new List<string>();
        var enc = new List<string>();
        foreach (var path in Directory.EnumerateFiles(volumeRoot, "*", SearchOption.AllDirectories))
        {
            var rel = MediaPaths.ToRelative(volumeRoot, path);
            if (IsExcluded(rel)) continue;
            if (MediaPaths.IsEncFile(path)) enc.Add(path);
            else plain.Add(path);
        }
        return (plain, enc);
    }

    private bool IsExcluded(string relativePath)
    {
        foreach (var prefix in Options.ExcludePrefixes)
            if (relativePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        var ext = Path.GetExtension(relativePath);
        return Options.ExcludeExtensions.Contains(ext);
    }

    private bool EncryptOne(string volumeRoot, VolumeManifest manifest, string plainPath,
                            CancellationToken ct)
    {
        var fi = new FileInfo(plainPath);
        if (fi.Length < Options.MinSizeBytes) return false;
        // skip files still being written: mtime must be at least ~1s old
        if (DateTimeOffset.UtcNow - fi.LastWriteTimeUtc < TimeSpan.FromSeconds(1)) return false;

        string rel = MediaPaths.ToRelative(volumeRoot, plainPath);
        var existing = manifest.ByPath.GetValueOrDefault(rel);
        if (existing?.State == FileState.Encrypted &&
            existing.Size == fi.Length && existing.MTime == fi.LastWriteTimeUtc)
            return false; // unchanged since last sync (fast path, no hashing)

        Guid fileId = existing != null ? Guid.Parse(existing.Id) : Guid.NewGuid();
        string encPath = MediaPaths.EncPathFor(plainPath);
        string tmpPath = encPath + ".tmp";
        ct.ThrowIfCancellationRequested();

        string sha;
        using (var src = OpenShared(plainPath))
        {
            sha = Convert.ToHexString(SHA256.HashData(src)).ToLowerInvariant();
            src.Position = 0;
            using var dst = new FileStream(tmpPath, FileMode.Create, FileAccess.Write,
                                           FileShare.None, 64 * 1024,
                                           FileOptions.WriteThrough);
            CryptoEngine.Encrypt(src, dst, keys.GetMasterKey(), fileId);
        }

        // atomic-ish swap on removable media: write .enc fully, flush, then delete original
        File.Move(tmpPath, encPath, overwrite: true);

        var entry = existing ?? new ManifestEntry
        {
            Id = fileId.ToString(),
            RelativePath = rel,
        };
        entry.Sha256Hex = sha;
        entry.Size = fi.Length;
        entry.MTime = fi.LastWriteTimeUtc;
        entry.State = FileState.Encrypted;
        entry.EncRelativePath = MediaPaths.ToRelative(volumeRoot, encPath);
        entry.UpdatedAt = DateTimeOffset.UtcNow;
        if (existing == null)
        {
            manifest.Entries.Add(entry);
            manifest.ByPath[rel] = entry;
        }

        if (Options.DeleteOriginals)
            TrySecureDelete(plainPath);
        return true;
    }

    private static FileStream OpenShared(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    private static void TrySecureDelete(string path)
    {
        try
        {
            // Single-pass overwrite is best-effort on flash (wear levelling maps
            // around it), but defeats simple undelete tools. See docs/THREAT_MODEL.md.
            var len = new FileInfo(path).Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var zeros = new byte[Math.Min(len, 1 << 20)];
                long left = len;
                while (left > 0)
                {
                    int n = (int)Math.Min(zeros.Length, left);
                    fs.Write(zeros, 0, n);
                    left -= n;
                }
                fs.SetLength(0);
                fs.Flush(true);
            }
            File.Delete(path);
        }
        catch (IOException) { /* locked by another process — retry next pass */ }
    }

    private void TrackError(VolumeManifest manifest, string volumeRoot, string plainPath, Exception ex)
    {
        string rel = MediaPaths.ToRelative(volumeRoot, plainPath);
        if (manifest.ByPath.TryGetValue(rel, out var e))
        {
            e.State = FileState.Error;
            e.UpdatedAt = DateTimeOffset.UtcNow;
        }
    }

    private static void TryDeleteStalePair(ManifestEntry entry, string encFull)
    {
        try
        {
            File.Delete(encFull); // remove outdated ciphertext; plaintext will be re-encrypted
            entry.State = FileState.PendingEncrypt;
            entry.UpdatedAt = DateTimeOffset.UtcNow;
        }
        catch (IOException) { }
    }
}
