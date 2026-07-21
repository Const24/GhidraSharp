namespace Const24.GhidraSharp.Tests.Contract;

/// <summary>
/// Drives the real <see cref="GhidraClient"/> against a <see cref="HappyFake"/>
/// server and asserts every RPC maps the wire reply to the right public record.
/// No Ghidra, no JVM — just the C# client + the proto contract.
/// </summary>
public sealed class MappingContractTests(HappyServerFixture fixture) : IClassFixture<HappyServerFixture>
{
    private GhidraClient Client => fixture.Client;

    [Fact]
    public async Task Ping_maps_version()
    {
        var info = await Client.PingAsync();
        Assert.Equal("test-version", info.GhidraVersion);
        Assert.Equal("test-server", info.ServerVersion);
    }

    [Fact]
    public async Task OpenProgram_maps_program_info()
    {
        var p = await Client.OpenProgramAsync("x");
        Assert.Equal("prog.bin", p.Name);
        Assert.Equal("Toy:LE:32:default", p.LanguageId);
        Assert.Equal(0x1000UL, p.ImageBase);
        Assert.Equal(7, p.FunctionCount);
    }

    [Fact]
    public async Task CreateProject_maps_program_info()
    {
        var p = await Client.CreateProjectAsync("b", "loc", "name");
        Assert.Equal("created.bin", p.Name);
        Assert.Equal(3, p.FunctionCount);
    }

    [Fact]
    public async Task Decompile_maps_result()
    {
        var d = await Client.DecompileAtAsync("0x1000");
        Assert.True(d.IsSuccess);
        Assert.Equal("void fn(void)", d.Signature);
        Assert.Equal("00001000", d.EntryPoint);
        Assert.Contains("return", d.CCode);
    }

    [Fact]
    public async Task DecompileMany_streams_all_results()
    {
        var results = new List<Decompilation>();
        await foreach (var d in Client.DecompileManyAsync(all: true))
        {
            results.Add(d);
        }
        Assert.Equal(2, results.Count);
        Assert.Equal("00001000", results[0].EntryPoint);
        Assert.Equal("00002000", results[1].EntryPoint);
    }

    [Fact]
    public async Task ListFunctions_maps_functions_and_calls()
    {
        var fns = await Client.ListFunctionsAsync(includeCalls: true);
        var fn = Assert.Single(fns);
        Assert.Equal("fn1", fn.Name);
        Assert.Equal("00001000", fn.EntryPoint);
        Assert.Equal(20UL, fn.Size);
        Assert.Equal(2, fn.ParameterCount);
        Assert.Equal(["callee_a", "callee_b"], fn.Calls);
    }

    [Fact]
    public async Task GetFunction_maps_detail_params_locals_callers()
    {
        var f = await Client.GetFunctionAtAsync("0x1000");
        Assert.Equal("int fn1(int p)", f.Signature);
        Assert.Equal("int", f.ReturnType);
        Assert.Equal("__stdcall", f.CallingConvention);
        var param = Assert.Single(f.Parameters);
        Assert.Equal("p", param.Name);
        Assert.Equal("int", param.DataType);
        Assert.Equal("r4:4", param.Storage);
        Assert.Equal("x", Assert.Single(f.Locals).Name);
        Assert.Equal("caller_a", Assert.Single(f.Callers));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetReferences_maps_xref(bool to)
    {
        var refs = to
            ? await Client.GetReferencesToAsync("0x1000")
            : await Client.GetReferencesFromAsync("0x1100");
        var r = Assert.Single(refs);
        Assert.Equal("00001100", r.FromAddress);
        Assert.Equal("00001000", r.ToAddress);
        Assert.Equal("UNCONDITIONAL_CALL", r.ReferenceType);
        Assert.True(r.IsCall);
        Assert.False(r.IsData);
    }

    [Fact]
    public async Task GetFunctionReferences_maps_xrefs()
    {
        var refs = await Client.GetFunctionReferencesAsync("0x1000");
        var r = Assert.Single(refs);
        Assert.Equal("00001100", r.FromAddress);
        Assert.True(r.IsCall);
    }

    [Fact]
    public async Task CloseProgram_succeeds() => await Client.CloseProgramAsync(); // HappyFake returns success -> must not throw

    [Fact]
    public async Task Symbols_map()
    {
        var s = Assert.Single(await Client.ListSymbolsAsync());
        Assert.Equal("main", s.Name);
        Assert.Equal("Function", s.SymbolType);
        Assert.Equal("USER_DEFINED", s.Source);
        Assert.True(s.IsPrimary);

        var at = Assert.Single(await Client.GetSymbolsAtAsync("0x1000"));
        Assert.Equal("main", at.Name);
    }

    [Fact]
    public async Task Data_and_types_map()
    {
        var d = await Client.GetDataAtAsync("0x3000");
        Assert.True(d.Defined);
        Assert.Equal("float", d.DataType);
        Assert.Equal(4, d.Length);
        Assert.Equal("1.5", d.Value);

        var applied = await Client.ApplyDataTypeAsync("0x3000", "float");
        Assert.Equal("float", applied.DataType);

        var t = Assert.Single(await Client.ListDataTypesAsync());
        Assert.Equal("int", t.Name);
        Assert.Equal("BuiltIn", t.Kind);
        Assert.Equal(4, t.Length);
    }

    [Fact]
    public async Task ReadBytes_maps_to_byte_array()
    {
        var bytes = await Client.ReadBytesAsync("0x1000", 2);
        Assert.Equal("ޭ"u8.ToArray(), bytes);
    }

    [Fact]
    public async Task Instructions_map()
    {
        var ins = Assert.Single(await Client.GetInstructionsAsync("0x1000"));
        Assert.Equal("mov", ins.Mnemonic);
        Assert.Equal("mov r1,r2", ins.Representation);
        Assert.Equal(new byte[] { 0x12, 0x34 }, ins.Bytes);
        Assert.Equal(2, ins.Length);
    }

    [Fact]
    public async Task InstructionDetail_maps_operands_and_pcode()
    {
        var d = await Client.GetInstructionDetailAsync("0x1000");
        Assert.Equal(new byte[] { 0xAB, 0xCD }, d.Bytes);
        Assert.Equal(2, d.Operands.Count);
        var scalarOp = d.Operands[1];
        Assert.True(scalarOp.HasScalar);
        Assert.Equal(16, scalarOp.Scalar);
        Assert.Equal("register", d.Operands[0].Type);
        var pcode = Assert.Single(d.Pcode);
        Assert.Equal("COPY", pcode.Mnemonic);
        Assert.Single(pcode.Inputs);
    }

    [Fact]
    public async Task Comments_map()
    {
        var c = await Client.GetCommentsAsync("0x1000");
        Assert.Equal("end of line", c.Eol);
        Assert.Equal("before", c.Pre);
        Assert.Equal("banner", c.Plate);
        Assert.Equal("", c.Post);
    }

    [Fact]
    public async Task Bookmarks_map()
    {
        var b = Assert.Single(await Client.GetBookmarksAsync("0x1000"));
        Assert.Equal("Note", b.Type);
        Assert.Equal("interesting", b.Comment);
    }

    [Fact]
    public async Task RunScript_maps_output()
    {
        var output = await Client.RunScriptAsync("script.java");
        Assert.Equal("hello from script", output.Stdout);
    }

    [Fact]
    public async Task SaveProgram_and_writes_do_not_throw_on_success()
    {
        await Client.SaveProgramAsync();
        await Client.RenameSymbolAtAsync("0x1000", "newName");
        await Client.SetBookmarkAsync("0x1000", comment: "n");
    }

    [Fact]
    public async Task ListMemoryBlocks_maps_block_range_and_permissions()
    {
        var b = Assert.Single(await Client.ListMemoryBlocksAsync());
        Assert.Equal(".text", b.Name);
        Assert.Equal("00001000", b.Start);
        Assert.Equal("00001fff", b.End);
        Assert.Equal(4096UL, b.Size);
        Assert.True(b.Initialized);
        Assert.True(b.Read);
        Assert.False(b.Write);
        Assert.True(b.Execute);
    }

    [Fact]
    public async Task FindStrings_maps_text_and_xrefs()
    {
        var s = Assert.Single(await Client.FindStringsAsync("config"));
        Assert.Equal("00002000", s.Address);
        Assert.Equal("config.ini", s.Text);
        Assert.False(s.IsUnicode);
        Assert.Equal("00001500", Assert.Single(s.XrefFrom));
    }
}
