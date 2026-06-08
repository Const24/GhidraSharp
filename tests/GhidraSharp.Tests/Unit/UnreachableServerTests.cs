namespace Const24.GhidraSharp.Tests.Unit;

public class UnreachableServerTests
{
    [Fact]
    public async Task A_call_to_an_unreachable_server_throws_a_helpful_GhidraException()
    {
        var port = GhidraServer.FindFreePort(); // nothing is listening on this port
        await using var client = GhidraClient.Connect($"http://127.0.0.1:{port}");

        var ex = await Assert.ThrowsAsync<GhidraException>(() => client.PingAsync());

        // The interceptor should point the user at the server download, not leak a raw RpcException.
        Assert.Contains("releases", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
