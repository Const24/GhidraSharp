using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Const24.GhidraSharp;

// Canonical dump of every bridged RPC plus per-capability timings, for a byte-for-byte
// comparison with the pyghidra twin (../pyghidra_extract.py — same calls, same format).
// Env: GHIDRASHARP_ARGFILE (java @argfile; defaults to server/build/ghidrasharp-java.args).

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: GhidraSharp.Parity <project.gpr|dir> <out-dir>");
    return 2;
}

var project = args[0];
var outDir = args[1];
Directory.CreateDirectory(outDir);

await using var server = await GhidraServer.StartAsync(new GhidraServerOptions
{
    ArgFile = Environment.GetEnvironmentVariable("GHIDRASHARP_ARGFILE") ?? "server/build/ghidrasharp-java.args",
});
var g = server.Client;

var info = await g.OpenProgramAsync(Path.GetFileNameWithoutExtension(project), projectPath: project);
Console.WriteLine($"[parity/cs] {info.Name} ({info.LanguageId}) functions={info.FunctionCount}");

var timings = new Dictionary<string, object>();
var funcs = new List<GhidraFunction>();

await Time("functions", async () =>
{
    funcs = [.. (await g.ListFunctionsAsync(includeCalls: true)).OrderBy(f => f.EntryPoint, StringComparer.Ordinal)];
    var sb = new StringBuilder();
    foreach (var f in funcs)
    {
        var calls = string.Join(";", f.Calls.OrderBy(c => c, StringComparer.Ordinal));
        sb.Append(CultureInfo.InvariantCulture, $"{f.EntryPoint}\t{f.Name}\t{f.Size}\t{f.ParameterCount}\t{Bool(f.IsThunk)}\t{calls}\n");
    }
    Write("functions.txt", sb);
    return funcs.Count;
});

await Time("symbols", async () =>
{
    var syms = (await g.ListSymbolsAsync(includeDynamic: false))
        .OrderBy(s => s.Address, StringComparer.Ordinal)
        .ThenBy(s => s.Name, StringComparer.Ordinal)
        .ThenBy(s => s.SymbolType, StringComparer.Ordinal).ToList();
    var sb = new StringBuilder();
    foreach (var s in syms)
    {
        sb.Append(CultureInfo.InvariantCulture, $"{s.Address}\t{s.Name}\t{s.SymbolType}\t{s.Source}\t{Bool(s.IsPrimary)}\t{Bool(s.IsGlobal)}\n");
    }
    Write("symbols.txt", sb);
    return syms.Count;
});

await Time("decompile", async () =>
{
    var results = new List<Decompilation>();
    await foreach (var d in g.DecompileManyAsync(all: true))
    {
        if (d.IsSuccess)
        {
            results.Add(d);
        }
    }
    results.Sort((a, b) => string.CompareOrdinal(a.EntryPoint, b.EntryPoint));
    var sb = new StringBuilder();
    foreach (var d in results)
    {
        sb.Append(CultureInfo.InvariantCulture, $">>> {d.EntryPoint}\n{d.CCode}");
    }

    Write("decompile.txt", sb);
    return results.Count;
});

await Time("instructions", async () =>
{
    var sb = new StringBuilder();
    var n = 0;
    foreach (var f in funcs)
    {
        foreach (var ins in await g.GetInstructionsAsync(f.EntryPoint))
        {
            sb.Append(CultureInfo.InvariantCulture, $"{ins.Address}\t{ins.Mnemonic}\t{ins.Representation}\n");
            n++;
        }
    }
    Write("instructions.txt", sb);
    return n;
});

await Time("xrefs_to", async () =>
{
    var sb = new StringBuilder();
    var n = 0;
    foreach (var f in funcs)
    {
        var refs = (await g.GetReferencesToAsync(f.EntryPoint))
            .OrderBy(r => r.FromAddress, StringComparer.Ordinal)
            .ThenBy(r => r.ReferenceType, StringComparer.Ordinal);
        foreach (var r in refs)
        {
            sb.Append(CultureInfo.InvariantCulture, $"{r.ToAddress}\t{r.FromAddress}\t{r.ReferenceType}\n");
            n++;
        }
    }
    Write("xrefs_to.txt", sb);
    return n;
});

await Time("bytes", async () =>
{
    var sb = new StringBuilder();
    foreach (var f in funcs)
    {
        var data = await g.ReadBytesAsync(f.EntryPoint, 16);
        sb.Append(CultureInfo.InvariantCulture, $"{f.EntryPoint}\t{Convert.ToHexString(data)}\n");
    }
    Write("bytes.txt", sb);
    return funcs.Count;
});

await Time("function_detail", async () =>
{
    var sb = new StringBuilder();
    foreach (var f in funcs)
    {
        var fd = await g.GetFunctionAtAsync(f.EntryPoint, includeCallers: true);
        var ps = string.Join(";", fd.Parameters.Select(p => $"{p.Name}|{p.DataType}|{p.Storage}"));
        var ls = string.Join(";", fd.Locals.Select(v => $"{v.Name}|{v.DataType}|{v.Storage}"));
        var callers = string.Join(";", fd.Callers.OrderBy(c => c, StringComparer.Ordinal));
        sb.Append(CultureInfo.InvariantCulture, $"{fd.EntryPoint}\t{fd.Signature}\t{fd.ReturnType}\t{fd.CallingConvention}"
                  + $"\t{Bool(fd.NoReturn)}\t{Bool(fd.VarArgs)}\t{Bool(fd.Inline)}\t{ps}\t{ls}\t{callers}\n");
    }
    Write("function_detail.txt", sb);
    return funcs.Count;
});

await Time("datatypes", async () =>
{
    var dts = (await g.ListDataTypesAsync())
        .OrderBy(d => d.Path, StringComparer.Ordinal)
        .ThenBy(d => d.Name, StringComparer.Ordinal)
        .ThenBy(d => d.Kind, StringComparer.Ordinal).ToList();
    var sb = new StringBuilder();
    foreach (var d in dts)
    {
        sb.Append(CultureInfo.InvariantCulture, $"{d.Path}\t{d.Name}\t{d.DisplayName}\t{d.Kind}\t{d.Length}\n");
    }
    Write("datatypes.txt", sb);
    return dts.Count;
});

File.WriteAllText(Path.Combine(outDir, "timings.json"),
    JsonSerializer.Serialize(timings, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"[parity/cs] done -> {outDir}");
return 0;

async Task Time(string name, Func<Task<int>> body)
{
    var sw = Stopwatch.StartNew();
    var count = await body();
    sw.Stop();
    timings[name] = new Dictionary<string, object> { ["ms"] = sw.ElapsedMilliseconds, ["count"] = count };
    Console.WriteLine($"[cs] {name}: {count} in {sw.ElapsedMilliseconds} ms");
}

void Write(string file, StringBuilder sb) => File.WriteAllText(Path.Combine(outDir, file), sb.ToString());

// Lowercase to stay byte-identical with the Python twin — bool.ToString() yields "True".
static string Bool(bool b) => b ? "true" : "false";
