namespace Const24.GhidraSharp.Tests.Contract;

/// <summary>Guard clauses reject bad arguments synchronously, before any RPC.</summary>
public sealed class ValidationContractTests(HappyServerFixture fixture) : IClassFixture<HappyServerFixture>
{
    private GhidraClient Client => fixture.Client;

    [Fact]
    public async Task Blank_addresses_and_names_throw_ArgumentException()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.DecompileAtAsync(""));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.DecompileByNameAsync(" "));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.GetReferencesToAsync(""));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.GetFunctionAtAsync(""));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.GetSymbolsAtAsync(""));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.OpenProgramAsync(""));
    }

    [Fact]
    public async Task ReadBytes_rejects_a_nonpositive_length() => await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.ReadBytesAsync("0x1000", 0));

    [Fact]
    public void Connect_rejects_a_blank_address() => Assert.ThrowsAny<ArgumentException>(() => GhidraClient.Connect(""));
}
