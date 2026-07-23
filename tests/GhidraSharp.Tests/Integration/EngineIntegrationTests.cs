using System.Diagnostics;

namespace Const24.GhidraSharp.Tests.Integration;

/// <summary>
/// Real end-to-end tests against a spawned Ghidra server, on a JVM target generated
/// at test time with <c>javac</c> (no committed binary, no private data). Skipped unless
/// <c>GHIDRA_INSTALL_DIR</c> is set and the server argfile exists (run
/// <c>server/gradlew writeServerArgs</c> first). JVM is a deliberate choice: its
/// <c>ram:</c>-prefixed addresses exercise the address-parsing regression.
/// </summary>
public sealed class IntegrationFixture : IAsyncLifetime
{
    public bool Available { get; private set; }
    public string SkipReason { get; private set; } = "";
    public GhidraClient Client => _server!.Client;
    public string GprPath { get; private set; } = "";
    public string ClassFile { get; private set; } = "";

    private GhidraServer? _server;
    private string? _staleServerDir;
    private string? _work;
    private string? _proj;

    public async ValueTask InitializeAsync()
    {
        // A developer's stale GHIDRASHARP_SERVER_DIR must never hijack the launch:
        // this suite always tests the source-built argfile server. Restored on dispose.
        _staleServerDir = Environment.GetEnvironmentVariable("GHIDRASHARP_SERVER_DIR");
        Environment.SetEnvironmentVariable("GHIDRASHARP_SERVER_DIR", null);

        var root = FindRepoRoot();
        var ghidra = Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
        var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        var argfile = root is null ? null : Path.Combine(root, "server", "build", "ghidrasharp-java.args");
        var javac = javaHome is null ? null
            : Path.Combine(javaHome, "bin", OperatingSystem.IsWindows() ? "javac.exe" : "javac");

        if (string.IsNullOrEmpty(ghidra) || argfile is null || !File.Exists(argfile) || javac is null || !File.Exists(javac))
        {
            SkipReason = "set GHIDRA_INSTALL_DIR + JAVA_HOME and run `server/gradlew writeServerArgs`";
            return;
        }

        // 1) build a tiny JVM target with javac
        _work = Directory.CreateTempSubdirectory("ghs_it_").FullName;
        var javaSrc = Path.Combine(_work, "Hello.java");
        await File.WriteAllTextAsync(javaSrc,
            "public class Hello {\n" +
            "  static int add(int a, int b) { return a + b; }\n" +
            "  public static void main(String[] x) { System.out.println(add(2, 3)); }\n" +
            "}\n");
        if (!await RunAsync(javac, ["-d", _work, javaSrc]) || !File.Exists(Path.Combine(_work, "Hello.class")))
        {
            SkipReason = "javac failed to build the JVM test target";
            return;
        }

        // 2) spawn the real server and create a persistent project from the .class
        _server = await GhidraServer.StartAsync(new GhidraServerOptions { ArgFile = argfile, GhidraInstallDir = ghidra });
        _proj = Directory.CreateTempSubdirectory("ghs_itproj_").FullName;
        await Client.CreateProjectAsync(Path.Combine(_work, "Hello.class"), _proj, "IT");
        GprPath = Path.Combine(_proj, "IT.gpr");
        ClassFile = Path.Combine(_work, "Hello.class");
        Available = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
        Environment.SetEnvironmentVariable("GHIDRASHARP_SERVER_DIR", _staleServerDir);
        TryDelete(_proj);
        TryDelete(_work);
        GC.SuppressFinalize(this);
    }

    private static string? FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "GhidraSharp.slnx")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName;
    }

    private static async Task<bool> RunAsync(string exe, string[] args)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardError = true };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using var p = Process.Start(psi)!;
        await p.WaitForExitAsync();
        return p.ExitCode == 0;
    }

    private static void TryDelete(string? dir)
    {
        try
        {
            if (dir is not null && Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }
}

// All tests share one server (the fixture) but NOT one program: several tests switch the
// server's current program (OpenProgram / transient import). The invariant is that no test
// assumes which program is current, and each leaves a program with functions open for the
// next. xUnit runs a class's tests sequentially, so the switches never interleave.
[Trait("Category", "Integration")]
[Collection("Ghidra servers")]
public sealed class EngineIntegrationTests(IntegrationFixture fixture) : IClassFixture<IntegrationFixture>
{
    private GhidraClient Client => fixture.Client;

    private async Task<string> FirstFunctionEntryAsync()
    {
        var fns = await Client.ListFunctionsAsync(ct: TestContext.Current.CancellationToken);
        Assert.NotEmpty(fns);
        return fns[0].EntryPoint;
    }

    [Fact]
    public async Task Opening_a_created_project_yields_functions()
    {
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var fns = await Client.ListFunctionsAsync(includeCalls: true, ct: TestContext.Current.CancellationToken);
        Assert.NotEmpty(fns);
    }

    [Fact]
    public async Task A_function_decompiles_to_nonempty_C()
    {
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();
        var dec = await Client.DecompileAtAsync(entry, ct: TestContext.Current.CancellationToken);
        Assert.True(dec.IsSuccess);
        Assert.False(string.IsNullOrWhiteSpace(dec.CCode));
    }

    [Fact]
    public async Task GetFunction_works_for_a_space_qualified_address()
    {
        // Regression: JVM entry points are "ram:...." — the address parser must handle them.
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();
        Assert.StartsWith("ram:", entry);
        var detail = await Client.GetFunctionAtAsync(entry, ct: TestContext.Current.CancellationToken);
        Assert.Equal(entry, detail.EntryPoint);
    }

    [Fact]
    public async Task Instruction_detail_is_readable()
    {
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();
        var detail = await Client.GetInstructionDetailAsync(entry, TestContext.Current.CancellationToken);
        Assert.Equal(entry, detail.Address);
        Assert.False(string.IsNullOrWhiteSpace(detail.Mnemonic));
    }

    [Fact]
    public async Task Rename_then_save_then_reopen_persists_the_name()
    {
        // Regression: edits must survive SaveProgram + a fresh read-only reopen.
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);

        // Self-sufficient on purpose: the class shares one client, and a sibling test may
        // have left a transiently-imported program on it (which SaveProgram rightly rejects).
        // Test order is not guaranteed, so open the persistent project writable here.
        var ct = TestContext.Current.CancellationToken;
        await Client.OpenProgramAsync("IT", projectPath: fixture.GprPath, writable: true, ct: ct);
        var entry = await FirstFunctionEntryAsync();

        await Client.RenameSymbolAtAsync(entry, "IntegrationRenamed", ct);
        await Client.SaveProgramAsync(ct);

        await Client.OpenProgramAsync("IT", projectPath: fixture.GprPath, writable: false, ct: ct);
        var symbols = await Client.GetSymbolsAtAsync(entry, ct);
        Assert.Contains(symbols, s => s.Name == "IntegrationRenamed");
    }

    [Fact]
    public async Task ListLanguages_returns_the_processor_catalog()
    {
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var langs = await Client.ListLanguagesAsync(ct: TestContext.Current.CancellationToken);
        Assert.NotEmpty(langs);
        Assert.Contains(langs, l => l.Id == "x86:LE:64:default"); // always present in Ghidra
    }

    [Fact]
    public async Task Importing_a_binary_transiently_needs_no_project()
    {
        // OpenProgram with a binary and no project path imports into a scratch program —
        // the "just show me the functions" path, no projectLocation/name.
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var ct = TestContext.Current.CancellationToken;
        var info = await Client.OpenProgramAsync(fixture.ClassFile, ct: ct); // JVM .class auto-detects the language
        Assert.True(info.FunctionCount > 0);

        var fns = await Client.ListFunctionsAsync(ct: ct);
        Assert.NotEmpty(fns);
        var dec = await Client.DecompileAtAsync(fns[0].EntryPoint, ct: ct);
        Assert.True(dec.IsSuccess);
    }

    [Fact]
    public async Task GetFunctionReferences_returns_a_functions_outgoing_refs()
    {
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var ct = TestContext.Current.CancellationToken;
        var fns = await Client.ListFunctionsAsync(ct: ct);

        var anyWithRefs = false;
        foreach (var fn in fns)
        {
            if ((await Client.GetFunctionReferencesAsync(fn.EntryPoint, ct)).Count > 0)
            {
                anyWithRefs = true;
                break;
            }
        }
        Assert.True(anyWithRefs); // e.g. main() references add()/println -> outgoing refs
    }

    [Fact]
    public async Task ListMemoryBlocks_returns_the_programs_sections()
    {
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var ct = TestContext.Current.CancellationToken;
        await Client.OpenProgramAsync(fixture.ClassFile, ct: ct);
        var blocks = await Client.ListMemoryBlocksAsync(ct);
        Assert.NotEmpty(blocks); // every loaded program has at least one memory block
        Assert.All(blocks, b => Assert.False(string.IsNullOrEmpty(b.Name)));
    }

    [Fact]
    public async Task FindStrings_runs_and_returns_a_list()
    {
        // Lenient smoke: a JVM .class may expose few or no Ghidra-defined strings, so we only
        // assert the RPC round-trips a well-formed list. Precise field mapping is covered by the
        // contract test against the fake server.
        Assert.SkipUnless(fixture.Available, fixture.SkipReason);
        var ct = TestContext.Current.CancellationToken;
        await Client.OpenProgramAsync(fixture.ClassFile, ct: ct);
        var all = await Client.FindStringsAsync(ct: ct); // null substring = every defined string
        Assert.NotNull(all);
        Assert.All(all, s => Assert.False(string.IsNullOrEmpty(s.Address)));
    }
}
