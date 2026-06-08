namespace Const24.GhidraSharp.Tests.Contract;

/// <summary>
/// The "list" RPCs put a whole result set in one message; on a large program that
/// can exceed gRPC's default 4 MB receive cap. The client raises the cap — this
/// test sends a ~5 MB reply and asserts it is received intact (it fails on the
/// 4 MB default).
/// </summary>
public class MessageSizeTests
{
    [Fact]
    public async Task ListFunctions_handles_a_reply_larger_than_the_default_4MB_cap()
    {
        await using var fake = await FakeServer.StartAsync<BigListFake>();

        var functions = await fake.Client.ListFunctionsAsync();

        Assert.Equal(BigListFake.Count, functions.Count);
    }
}
