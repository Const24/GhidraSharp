namespace Const24.GhidraSharp.Tests.Contract;

/// <summary>A failing server should surface as <see cref="GhidraException"/> on the
/// throwing methods, and as <c>IsSuccess=false</c> on the streaming/batch decompile.</summary>
public sealed class ErrorContractTests(FailingServerFixture fixture) : IClassFixture<FailingServerFixture>
{
    private GhidraClient Client => fixture.Client;

    [Fact]
    public async Task OpenProgram_throws_GhidraException_with_server_error()
    {
        var ex = await Assert.ThrowsAsync<GhidraException>(() => Client.OpenProgramAsync("x"));
        Assert.Contains("boom", ex.Message);
    }

    [Fact]
    public async Task Throwing_reads_raise_GhidraException()
    {
        await Assert.ThrowsAsync<GhidraException>(() => Client.ListFunctionsAsync());
        await Assert.ThrowsAsync<GhidraException>(() => Client.GetReferencesToAsync("0x1000"));
        await Assert.ThrowsAsync<GhidraException>(() => Client.ListSymbolsAsync());
        await Assert.ThrowsAsync<GhidraException>(() => Client.GetDataAtAsync("0x1000"));
        await Assert.ThrowsAsync<GhidraException>(() => Client.GetFunctionAtAsync("0x1000"));
        await Assert.ThrowsAsync<GhidraException>(() => Client.RunScriptAsync("s.java"));
        await Assert.ThrowsAsync<GhidraException>(() => Client.SaveProgramAsync());
    }

    [Fact]
    public async Task Decompile_reports_failure_without_throwing()
    {
        var d = await Client.DecompileAtAsync("0x1000");
        Assert.False(d.IsSuccess);
        Assert.Contains("boom", d.Error);
    }

    [Fact]
    public async Task SetComment_sends_the_CommentType_as_its_wire_name()
    {
        // CapturingFake echoes the received type back as the error.
        await using var fake = await FakeServer.StartAsync<CapturingFake>();
        var ex = await Assert.ThrowsAsync<GhidraException>(
            () => fake.Client.SetCommentAsync("0x1000", CommentType.Plate, "note"));
        Assert.Contains("Plate", ex.Message);
    }
}
