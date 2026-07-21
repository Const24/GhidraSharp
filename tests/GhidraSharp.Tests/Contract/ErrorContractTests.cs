namespace Const24.GhidraSharp.Tests.Contract;

/// <summary>A failing server surfaces as <see cref="GhidraException"/> naming the operation
/// on the throwing methods, and as <c>IsSuccess=false</c> on the single/streaming decompile.</summary>
public sealed class ErrorContractTests(FailingServerFixture fixture) : IClassFixture<FailingServerFixture>
{
    private GhidraClient Client => fixture.Client;

    public static TheoryData<string, Func<GhidraClient, Task>> ThrowingCalls => new()
    {
        { "OpenProgram", c => c.OpenProgramAsync("x") },
        { "CreateProject", c => c.CreateProjectAsync("bin", "loc", "name") },
        { "SaveProgram", c => c.SaveProgramAsync() },
        { "CloseProgram", c => c.CloseProgramAsync() },
        { "ListFunctions", c => c.ListFunctionsAsync() },
        { "GetFunction", c => c.GetFunctionAtAsync("0x1000") },
        { "GetReferencesTo", c => c.GetReferencesToAsync("0x1000") },
        { "GetReferencesFrom", c => c.GetReferencesFromAsync("0x1000") },
        { "GetFunctionReferences", c => c.GetFunctionReferencesAsync("0x1000") },
        { "ListSymbols", c => c.ListSymbolsAsync() },
        { "GetSymbolsAt", c => c.GetSymbolsAtAsync("0x1000") },
        { "RenameSymbol", c => c.RenameSymbolAtAsync("0x1000", "n") },
        { "FindStrings", c => c.FindStringsAsync("cfg") },
        { "ReadBytes", c => c.ReadBytesAsync("0x1000", 4) },
        { "GetInstructions", c => c.GetInstructionsAsync("0x1000") },
        { "GetInstructionDetail", c => c.GetInstructionDetailAsync("0x1000") },
        { "GetDataAt", c => c.GetDataAtAsync("0x1000") },
        { "ApplyDataType", c => c.ApplyDataTypeAsync("0x1000", "int") },
        { "ListDataTypes", c => c.ListDataTypesAsync() },
        { "GetComments", c => c.GetCommentsAsync("0x1000") },
        { "SetComment", c => c.SetCommentAsync("0x1000", CommentType.Eol, "n") },
        { "GetBookmarks", c => c.GetBookmarksAsync("0x1000") },
        { "SetBookmark", c => c.SetBookmarkAsync("0x1000") },
        { "ListMemoryBlocks", c => c.ListMemoryBlocksAsync() },
        { "ListLanguages", c => c.ListLanguagesAsync() },
        { "RunScript", c => c.RunScriptAsync("s.java") },
    };

    [Theory]
    [MemberData(nameof(ThrowingCalls))]
    public async Task Every_throwing_RPC_names_its_operation_and_carries_the_server_error(
        string operation, Func<GhidraClient, Task> call)
    {
        var ex = await Assert.ThrowsAsync<GhidraException>(() => call(Client));
        Assert.StartsWith($"{operation} failed: ", ex.Message, StringComparison.Ordinal);
        Assert.Contains("boom", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Decompile_reports_failure_without_throwing()
    {
        var d = await Client.DecompileAtAsync("0x1000");
        Assert.False(d.IsSuccess);
        Assert.Contains("boom", d.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DecompileMany_surfaces_a_streamed_failure_without_throwing()
    {
        var results = new List<Decompilation>();
        await foreach (var d in Client.DecompileManyAsync(all: true))
        {
            results.Add(d);
        }
        var r = Assert.Single(results);
        Assert.False(r.IsSuccess);
        Assert.Contains("boom", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SetComment_sends_the_CommentType_as_its_wire_name()
    {
        // CapturingFake echoes the received type back as the error.
        await using var fake = await FakeServer.StartAsync<CapturingFake>();
        var ex = await Assert.ThrowsAsync<GhidraException>(
            () => fake.Client.SetCommentAsync("0x1000", CommentType.Plate, "note"));
        Assert.Contains("Plate", ex.Message, StringComparison.Ordinal);
    }
}
