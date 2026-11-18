namespace UsbGuard.Core.Storage;

/// <summary>
/// Filesystem helpers for the sync pipeline. All operations are crash-safe:
/// writes go to a temp file + atomic replace; the manifest keeps one backup copy.
/// </summary>
public static class MediaPaths
{
    public const string MetaDirName = ".usbguard";
    public const string ManifestName = "manifest.json";
    public const string EncSuffix = ".usbguard.enc";

    public static string ManifestPath(string volumeRoot) =>
        Path.Combine(volumeRoot, MetaDirName, ManifestName);

    public static string ManifestBackupPath(string volumeRoot) =>
        Path.Combine(volumeRoot, MetaDirName, ManifestName + ".bak");

    public static string EncPathFor(string plainPath) => plainPath + EncSuffix;

    public static bool IsEncFile(string path) =>
        path.EndsWith(EncSuffix, StringComparison.OrdinalIgnoreCase);

    public static string PlainPathFor(string encPath)
    {
        if (!IsEncFile(encPath))
            throw new ArgumentException($"not an {EncSuffix} path: {encPath}", nameof(encPath));
        return encPath[..^EncSuffix.Length];
    }

    /// <summary>Normalises a full path under volumeRoot into a manifest-relative '/' path.</summary>
    public static string ToRelative(string volumeRoot, string fullPath)
    {
        var root = volumeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"path {fullPath} is not under {volumeRoot}", nameof(fullPath));
        var rel = fullPath[root.Length..].TrimStart('\\', '/').Replace('\\', '/');
        return rel;
    }

    public static string FromRelative(string volumeRoot, string relative) =>
        Path.Combine(volumeRoot, relative.Replace('/', Path.DirectorySeparatorChar));
}

/// <summary>Atomic JSON persistence for <see cref="VolumeManifest"/>.</summary>
public sealed class ManifestStore
{
    private readonly string _volumeRoot;

    public ManifestStore(string volumeRoot) => _volumeRoot = volumeRoot;

    public VolumeManifest Load()
    {
        string main = MediaPaths.ManifestPath(_volumeRoot);
        string bak = MediaPaths.ManifestBackupPath(_volumeRoot);
        foreach (var p in new[] { main, bak })
        {
            if (!File.Exists(p)) continue;
            try
            {
                var m = System.Text.Json.JsonSerializer.Deserialize<VolumeManifest>(
                    File.ReadAllText(p), VolumeManifest.JsonOpts);
                if (m != null) { m.Reindex(); return m; }
            }
            catch (System.Text.Json.JsonException) { /* fall through to backup */ }
        }
        return new VolumeManifest
        {
            VolumeId = ComputeVolumeId(_volumeRoot),
        };
    }

    public void Save(VolumeManifest manifest)
    {
        Directory.CreateDirectory(Path.Combine(_volumeRoot, MediaPaths.MetaDirName));
        string main = MediaPaths.ManifestPath(_volumeRoot);
        string tmp = main + ".tmp";
        File.WriteAllText(tmp, System.Text.Json.JsonSerializer.Serialize(manifest, VolumeManifest.JsonOpts));
        if (File.Exists(main))
            File.Copy(main, MediaPaths.ManifestBackupPath(_volumeRoot), overwrite: true);
        File.Move(tmp, main, overwrite: true);
    }

    /// <summary>
    /// Stable media identity: on Windows this is derived from the volume serial
    /// number + filesystem label; injected here via callback so Core stays portable.
    /// </summary>
    public static Func<string, string> VolumeIdProvider { get; set; } =
        static root => "vol-" + Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(root))).ToLowerInvariant()[..16];

    public static string ComputeVolumeId(string volumeRoot) => VolumeIdProvider(volumeRoot);
}
