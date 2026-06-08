namespace Const24.GhidraSharp.Tests.Contract;

public class VersionSkewTests
{
    [Fact]
    public async Task Calling_an_RPC_an_older_server_lacks_throws_a_helpful_GhidraException()
    {
        // BareFake implements nothing, so every RPC comes back UNIMPLEMENTED — exactly what a
        // server older than the client does for a newer RPC.
        await using var fake = await FakeServer.StartAsync<BareFake>();

        var ex = await Assert.ThrowsAsync<GhidraException>(() => fake.Client.ListLanguagesAsync());

        Assert.Contains("does not implement", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
