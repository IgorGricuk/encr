using System.Security.Cryptography;
using UsbGuard.Core.Crypto;
using Xunit;

namespace UsbGuard.Core.Tests;

public class KeyProviderTests
{
    private static string TempDir()
    {
        var p = Path.Combine(Path.GetTempPath(), "usbguard-keys-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        return p;
    }

    [Fact]
    public void MasterKey_Is_Stable_Across_Instances()
    {
        var dir = TempDir();
        var k1 = new FileKeyProvider(dir).GetMasterKey();
        var k2 = new FileKeyProvider(dir).GetMasterKey();
        Assert.Equal(k1, k2);
        Assert.Equal(32, k1.Length);
        Directory.Delete(dir, true);
    }

    [Fact]
    public void Backup_Export_Import_Roundtrip()
    {
        var dirA = TempDir();
        var master = new FileKeyProvider(dirA).GetMasterKey();
        var backup = new FileKeyProvider(dirA).ExportBackup("correct horse battery staple");

        var dirB = TempDir();
        var providerB = new FileKeyProvider(dirB);
        providerB.ImportBackup(backup, "correct horse battery staple");
        Assert.Equal(master, providerB.GetMasterKey());
        Directory.Delete(dirA, true);
        Directory.Delete(dirB, true);
    }

    [Fact]
    public void Backup_Wrong_Passphrase_Rejected()
    {
        var dir = TempDir();
        var backup = new FileKeyProvider(dir).ExportBackup("right");
        var dir2 = TempDir();
        Assert.Throws<CryptographicException>(() =>
            new FileKeyProvider(dir2).ImportBackup(backup, "wrong"));
        Directory.Delete(dir, true);
        Directory.Delete(dir2, true);
    }
}
