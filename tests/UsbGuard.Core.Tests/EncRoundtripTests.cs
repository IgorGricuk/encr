using System.Security.Cryptography;
using System.Text;
using UsbGuard.Core.Crypto;
using Xunit;

namespace UsbGuard.Core.Tests;

public class EncRoundtripTests
{
    private static byte[] MasterKey() => RandomNumberGenerator.GetBytes(32);

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4096)]
    [InlineData(1_000_000)]           // < chunk
    [InlineData(1 << 20)]             // == chunk
    [InlineData((1 << 20) + 7)]       // > chunk
    [InlineData(3 * (1 << 20) + 123)] // multi-chunk
    public void Encrypt_Then_Decrypt_Restores_Plaintext(int size)
    {
        var master = MasterKey();
        var plain = RandomNumberGenerator.GetBytes(size);
        var fileId = Guid.NewGuid();

        var enc = new MemoryStream();
        CryptoEngine.Encrypt(new MemoryStream(plain), enc, master, fileId, chunkSize: 1 << 20);
        enc.Position = 0;

        var dec = new MemoryStream();
        CryptoEngine.Decrypt(enc, dec, master);
        Assert.Equal(plain, dec.ToArray());
    }

    [Fact]
    public void Decrypt_With_Wrong_Key_Fails_Authentication()
    {
        var enc = new MemoryStream();
        CryptoEngine.Encrypt(new MemoryStream(Encoding.UTF8.GetBytes("secret data")),
                             enc, MasterKey(), Guid.NewGuid(), chunkSize: 1 << 20);
        enc.Position = 0;
        Assert.Throws<CorruptedEncFileException>(() =>
            CryptoEngine.Decrypt(enc, new MemoryStream(), MasterKey()));
    }

    [Fact]
    public void Decrypt_Detects_Tampering()
    {
        var master = MasterKey();
        var enc = new MemoryStream();
        CryptoEngine.Encrypt(new MemoryStream(Encoding.UTF8.GetBytes("hello world")),
                             enc, master, Guid.NewGuid(), chunkSize: 1 << 20);
        var bytes = enc.ToArray();
        bytes[bytes.Length - 1] ^= 0xFF; // flip a bit in the GCM tag
        Assert.Throws<CorruptedEncFileException>(() =>
            CryptoEngine.Decrypt(new MemoryStream(bytes), new MemoryStream(), master));
    }

    [Fact]
    public void Header_Preserves_FileId_And_Length()
    {
        var master = MasterKey();
        var id = Guid.NewGuid();
        var enc = new MemoryStream();
        CryptoEngine.Encrypt(new MemoryStream(new byte[1234]), enc, master, id, chunkSize: 1 << 20);
        enc.Position = 0;
        var h = CryptoEngine.PeekHeader(enc);
        Assert.Equal(id, h.FileId);
        Assert.Equal(1234, h.PlainLength);
    }

    [Fact]
    public void IsEncFile_Recognises_Container()
    {
        var enc = new MemoryStream();
        CryptoEngine.Encrypt(new MemoryStream(new byte[10]), enc, MasterKey(), Guid.NewGuid(), 1 << 20);
        enc.Position = 0;
        Assert.True(EncFileReader.IsEncFile(enc));

        var txt = new MemoryStream(Encoding.UTF8.GetBytes("just a text file, definitely not encrypted"));
        Assert.False(EncFileReader.IsEncFile(txt));
    }
}
