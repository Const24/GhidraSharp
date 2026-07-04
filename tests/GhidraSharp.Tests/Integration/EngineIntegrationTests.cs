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
    private string? _work;
    private string? _proj;

    public async Task InitializeAsync()
    {
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

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
        TryDelete(_proj);
        TryDelete(_work);
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
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        await p.WaitForExitAsync();
        return p.ExitCode == 0;
    }

    private static void TryDelete(string? dir)
    {
        try
        {
            if (dir is not null && Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
        catch
        {
            // best effort
        }
    }
}

// All tests in this class share one server + one current program (the fixture) and
// key off addresses, never names — so the single mutating test (rename) can't affect
// the others regardless of run order. xUnit also runs a class's tests sequentially.
[Trait("Category", "Integration")]
[Collection("Ghidra servers")]
public sealed class EngineIntegrationTests(IntegrationFixture fixture) : IClassFixture<IntegrationFixture>
{
    private GhidraClient Client => fixture.Client;

    private async Task<string> FirstFunctionEntryAsync()
    {
        var fns = await Client.ListFunctionsAsync();
        Assert.NotEmpty(fns);
        return fns[0].EntryPoint;
    }

    [SkippableFact]
    public async Task Opening_a_created_project_yields_functions()
    {
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var fns = await Client.ListFunctionsAsync(includeCalls: true);
        Assert.NotEmpty(fns);
    }

    [SkippableFact]
    public async Task A_function_decompiles_to_nonempty_C()
    {
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();
        var dec = await Client.DecompileAtAsync(entry);
        Assert.True(dec.IsSuccess);
        Assert.False(string.IsNullOrWhiteSpace(dec.CCode));
    }

    [SkippableFact]
    public async Task GetFunction_works_for_a_space_qualified_address()
    {
        // Regression: JVM entry points are "ram:...." — the address parser must handle them.
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();
        Assert.StartsWith("ram:", entry);
        var detail = await Client.GetFunctionAtAsync(entry);
        Assert.Equal(entry, detail.EntryPoint);
    }

    [SkippableFact]
    public async Task Instruction_detail_is_readable()
    {
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();
        var detail = await Client.GetInstructionDetailAsync(entry);
        Assert.Equal(entry, detail.Address);
        Assert.False(string.IsNullOrWhiteSpace(detail.Mnemonic));
    }

    [SkippableFact]
    public async Task Rename_then_save_then_reopen_persists_the_name()
    {
        // Regression: edits must survive SaveProgram + a fresh read-only reopen.
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var entry = await FirstFunctionEntryAsync();

        await Client.RenameSymbolAtAsync(entry, "IntegrationRenamed");
        await Client.SaveProgramAsync();

        await Client.OpenProgramAsync("IT", projectPath: fixture.GprPath, writable: false);
        var symbols = await Client.GetSymbolsAtAsync(entry);
        Assert.Contains(symbols, s => s.Name == "IntegrationRenamed");
    }

    [SkippableFact]
    public async Task ListLanguages_returns_the_processor_catalog()
    {
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var langs = await Client.ListLanguagesAsync();
        Assert.NotEmpty(langs);
        Assert.Contains(langs, l => l.Id == "x86:LE:64:default"); // always present in Ghidra
    }

    [SkippableFact]
    public async Task Importing_a_binary_transiently_needs_no_project()
    {
        // OpenProgram with a binary and no project path imports into a scratch program —
        // the "just show me the functions" path, no projectLocation/name.
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var info = await Client.OpenProgramAsync(fixture.ClassFile); // JVM .class auto-detects the language
        Assert.True(info.FunctionCount > 0);

        var fns = await Client.ListFunctionsAsync();
        Assert.NotEmpty(fns);
        var dec = await Client.DecompileAtAsync(fns[0].EntryPoint);
        Assert.True(dec.IsSuccess);
    }

    [SkippableFact]
    public async Task GetFunctionReferences_returns_a_functions_outgoing_refs()
    {
        Skip.IfNot(fixture.Available, fixture.SkipReason);
        var fns = await Client.ListFunctionsAsync();

        var anyWithRefs = false;
        foreach (var fn in fns)
        {
            if ((await Client.GetFunctionReferencesAsync(fn.EntryPoint)).Count > 0)
            {
                anyWithRefs = true;
                break;
            }
        }
        Assert.True(anyWithRefs); // e.g. main() references add()/println -> outgoing refs
    }
}
