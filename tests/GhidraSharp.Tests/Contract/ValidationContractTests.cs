namespace Const24.GhidraSharp.Tests.Contract;

/// <summary>Guard clauses reject bad arguments synchronously, before any RPC.</summary>
public sealed class ValidationContractTests(HappyServerFixture fixture) : IClassFixture<HappyServerFixture>
{
    private GhidraClient Client => fixture.Client;

    [Fact]
    public async Task Blank_addresses_and_names_throw_ArgumentException()
    {
        var ct = TestContext.Current.CancellationToken;
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.DecompileAtAsync("", ct: ct));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.DecompileByNameAsync(" ", ct: ct));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.GetReferencesToAsync("", ct));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.GetFunctionAtAsync("", ct: ct));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.GetSymbolsAtAsync("", ct));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Client.OpenProgramAsync("", ct: ct));
    }

    [Fact]
    public async Task ReadBytes_rejects_a_nonpositive_length() =>
        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => Client.ReadBytesAsync("0x1000", 0, TestContext.Current.CancellationToken));

    [Fact]
    public void Connect_rejects_a_blank_address() => Assert.ThrowsAny<ArgumentException>(() => GhidraClient.Connect(""));
}
