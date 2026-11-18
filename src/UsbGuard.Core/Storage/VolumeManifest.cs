using System.Text.Json;
using System.Text.Json.Serialization;

namespace UsbGuard.Core.Storage;

public enum FileState
{
    /// <summary>Plaintext on media, not yet encrypted by the agent.</summary>
    PendingEncrypt,
    /// <summary>Encrypted; .enc present, original removed.</summary>
    Encrypted,
    /// <summary>Deleted on media since last scan.</summary>
    Deleted,
    /// <summary>Agent failed to process it (locked, IO error…); will retry.</summary>
    Error,
}

/// <summary>One row of the per-volume manifest (.usbguard/manifest.json).</summary>
public sealed class ManifestEntry
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }               // GUID string, also embedded in .enc header

    [JsonPropertyName("path")]
    public required string RelativePath { get; set; }     // relative to volume root, '/' separators

    [JsonPropertyName("sha256")]
    public string? Sha256Hex { get; set; }                // hash of plaintext at encryption time

    [JsonPropertyName("size")]
    public long Size { get; set; }                        // plaintext size

    [JsonPropertyName("mtime")]
    public DateTimeOffset MTime { get; set; }             // source mtime at encryption time

    [JsonPropertyName("state")]
    [JsonConverter(typeof(JsonStringEnumConverter<FileState>))]
    public FileState State { get; set; }

    [JsonPropertyName("encPath")]
    public string? EncRelativePath { get; set; }          // e.g. "docs/report.xlsx.usbguard.enc"

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class VolumeManifest
{
    public const int CurrentVersion = 1;

    [JsonPropertyName("version")]
    public int Version { get; set; } = CurrentVersion;

    /// <summary>Stable per-media id (volume serial + disk signature). Survives re-plugging.</summary>
    [JsonPropertyName("volumeId")]
    public required string VolumeId { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("entries")]
    public List<ManifestEntry> Entries { get; set; } = new();

    [JsonIgnore]
    public Dictionary<string, ManifestEntry> ByPath { get; private set; } = new();

    /// <summary>Rebuilds the path index after load or external mutation.</summary>
    public void Reindex() =>
        ByPath = Entries.GroupBy(e => e.RelativePath, StringComparer.Ordinal)
                        .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);

    internal static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
