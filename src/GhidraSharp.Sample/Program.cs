using Const24.GhidraSharp;

// Smoke / demo client for the GhidraSharp bridge.
//
//   GhidraSharp.Sample [--server http://127.0.0.1:50080 | --spawn [--argfile <path>]]
//                      [--rom <path-or-domainfile>] [--project <gpr>] [--lang <id>]
//                      [--addr 0x21e0 | --name FUN_000021e0]
//                      [--list [--calls FUN_xxxx]]
//                      [--xrefs 0x30d1c]
//                      [--decompile-all [--dump <file>]]
//
// --spawn starts (and stops) its own Java server; otherwise it connects to one
// already running at --server.

var opts = ParseArgs(args);
var server = opts.GetValueOrDefault("server", "http://127.0.0.1:50080");

GhidraServer? spawned = null;
GhidraClient ghidra;
if (opts.ContainsKey("spawn"))
{
    spawned = await GhidraServer.StartAsync(new GhidraServerOptions
    {
        ArgFile = opts.GetValueOrDefault("argfile", "server/build/ghidrasharp-java.args"),
    });
    Console.WriteLine($"[spawn] server started on port {spawned.Port}");
    ghidra = spawned.Client;
}
else
{
    ghidra = GhidraClient.Connect(server);
}

try
{
    return await Run(ghidra, opts, server);
}
finally
{
    if (spawned is not null) await spawned.DisposeAsync();
    else await ghidra.DisposeAsync();
}

static async Task<int> Run(GhidraClient ghidra, Dictionary<string, string> opts, string server)
{
    try
    {
        var info = await ghidra.PingAsync();
        Console.WriteLine($"[ping] server up, Ghidra {info.GhidraVersion}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[ping] could not reach server at {server}: {ex.Message}");
        return 1;
    }

    if (opts.TryGetValue("create-project", out var cpBinary))
    {
        var created = await ghidra.CreateProjectAsync(
            cpBinary,
            opts.GetValueOrDefault("proj-loc", "."),
            opts.GetValueOrDefault("proj-name", "ghidrasharp"),
            opts.GetValueOrDefault("lang", ""));
        Console.WriteLine($"[create-project] {created.Name} ({created.LanguageId}) functions={created.FunctionCount}");
    }
    else if (opts.TryGetValue("rom", out var rom))
    {
        try
        {
            var program = await ghidra.OpenProgramAsync(
                rom,
                projectPath: opts.GetValueOrDefault("project", ""),
                languageId: opts.GetValueOrDefault("lang", ""),
                writable: opts.ContainsKey("writable"));
            Console.WriteLine(
                $"[open] {program.Name} ({program.LanguageId}) base=0x{program.ImageBase:x} functions={program.FunctionCount}");
        }
        catch (GhidraException ex)
        {
            Console.Error.WriteLine($"[open] {ex.Message}");
            return 2;
        }
    }
    else
    {
        return 0;
    }

    var addr = opts.GetValueOrDefault("addr", "");
    var name = opts.GetValueOrDefault("name", "");
    if (addr.Length > 0 || name.Length > 0)
    {
        var dec = addr.Length > 0
            ? await ghidra.DecompileAtAsync(addr)
            : await ghidra.DecompileByNameAsync(name);

        if (!dec.IsSuccess)
        {
            Console.Error.WriteLine($"[decompile] failed: {dec.Error}");
            return 3;
        }

        Console.WriteLine($"[decompile] {dec.Signature}  @ {dec.EntryPoint}");
        Console.WriteLine(dec.CCode);
    }

    if (opts.ContainsKey("list"))
    {
        var funcs = await ghidra.ListFunctionsAsync(includeCalls: true);
        Console.WriteLine($"[list] {funcs.Count} functions");

        // The whole point of the migration: query the program with LINQ.
        Console.WriteLine("[linq] 5 largest functions:");
        foreach (var f in funcs.OrderByDescending(f => f.Size).Take(5))
        {
            Console.WriteLine($"  {f.EntryPoint}  {f.Size,6}b  {f.ParameterCount}p  {f.Name}");
        }

        var hubs = funcs.Count(f => f.Calls.Count >= 10);
        Console.WriteLine($"[linq] functions that call >=10 others: {hubs}");

        if (opts.TryGetValue("calls", out var callee))
        {
            var callers = funcs.Where(f => f.Calls.Contains(callee)).OrderBy(f => f.Name).ToList();
            Console.WriteLine($"[linq] {callers.Count} functions call \"{callee}\":");
            foreach (var f in callers.Take(10)) Console.WriteLine($"  {f.EntryPoint}  {f.Name}");
        }
    }

    if (opts.TryGetValue("xrefs", out var xrefAddr))
    {
        var to = await ghidra.GetReferencesToAsync(xrefAddr);
        Console.WriteLine($"[xrefs] {to.Count} references TO {xrefAddr}");
        foreach (var g in to.GroupBy(r => r.ReferenceType).OrderByDescending(g => g.Count()))
        {
            Console.WriteLine($"  {g.Count(),4}x {g.Key}");
        }

        var callSites = to.Where(r => r.IsCall).Select(r => r.FromAddress).ToList();
        Console.WriteLine($"[xrefs] called from {callSites.Count} sites: {string.Join(", ", callSites.Take(8))}");
    }

    if (opts.ContainsKey("symbols"))
    {
        var syms = await ghidra.ListSymbolsAsync(includeDynamic: false);
        Console.WriteLine($"[symbols] {syms.Count} non-dynamic symbols");
        foreach (var g in syms.GroupBy(s => s.SymbolType).OrderByDescending(g => g.Count()))
        {
            Console.WriteLine($"  {g.Count(),5}x {g.Key}");
        }
    }

    if (opts.TryGetValue("symbols-at", out var symAddr))
    {
        var at = await ghidra.GetSymbolsAtAsync(symAddr);
        Console.WriteLine($"[symbols-at {symAddr}] {at.Count}:");
        foreach (var s in at) Console.WriteLine($"  {s.Name}  [{s.SymbolType}, {s.Source}{(s.IsPrimary ? ", primary" : "")}]");
    }

    if (opts.TryGetValue("rename-at", out var renAddr) && opts.TryGetValue("to", out var newName))
    {
        var before = await ghidra.GetSymbolsAtAsync(renAddr);
        Console.WriteLine($"[rename] {renAddr}: \"{before.FirstOrDefault()?.Name}\" -> \"{newName}\"");
        await ghidra.RenameSymbolAtAsync(renAddr, newName);
        var after = await ghidra.GetSymbolsAtAsync(renAddr);
        Console.WriteLine($"[rename] now: \"{after.FirstOrDefault()?.Name}\" (in-memory; not saved)");
    }

    if (opts.TryGetValue("bytes", out var bytesAddr))
    {
        var len = int.TryParse(opts.GetValueOrDefault("len", "16"), out var l) ? l : 16;
        var data = await ghidra.ReadBytesAsync(bytesAddr, len);
        Console.WriteLine($"[bytes {bytesAddr}] {data.Length}: {Convert.ToHexString(data)}");
    }

    if (opts.TryGetValue("disasm", out var disAddr))
    {
        var count = int.TryParse(opts.GetValueOrDefault("count", "12"), out var c) ? c : 12;
        var instrs = await ghidra.GetInstructionsAsync(disAddr, count);
        Console.WriteLine($"[disasm {disAddr}] {instrs.Count} instructions:");
        foreach (var ins in instrs)
        {
            Console.WriteLine($"  {ins.Address}  {Convert.ToHexString(ins.Bytes),-10} {ins.Representation}");
        }
    }

    if (opts.TryGetValue("function", out var fnAddr))
    {
        var fd = await ghidra.GetFunctionAtAsync(fnAddr);
        Console.WriteLine($"[function] {fd.Signature}");
        Console.WriteLine($"  entry={fd.EntryPoint} size={fd.Size} cc={fd.CallingConvention} ret={fd.ReturnType} "
                          + $"noReturn={fd.NoReturn} varArgs={fd.VarArgs}");
        var ps = fd.Parameters.Count == 0
            ? "(none)"
            : string.Join(", ", fd.Parameters.Select(p => $"{p.DataType} {p.Name}@{p.Storage}"));
        Console.WriteLine($"  params: {ps}");
        Console.WriteLine($"  locals: {fd.Locals.Count}, callers: {fd.Callers.Count}");
    }

    if (opts.TryGetValue("data", out var dataAddr))
    {
        var d = await ghidra.GetDataAtAsync(dataAddr);
        Console.WriteLine(d.Defined
            ? $"[data {dataAddr}] {d.DataType} len={d.Length} value={d.Value}{(d.IsPointer ? $" -> {d.PointerTarget}" : "")}"
            : $"[data {dataAddr}] (no defined data)");
    }

    if (opts.TryGetValue("datatypes", out var dtFilter))
    {
        var filter = dtFilter == "true" ? null : dtFilter;
        var dts = await ghidra.ListDataTypesAsync(filter);
        Console.WriteLine($"[datatypes] {dts.Count}{(filter is null ? "" : $" matching \"{filter}\"")}");
        foreach (var g in dts.GroupBy(d => d.Kind).OrderByDescending(g => g.Count()))
        {
            Console.WriteLine($"  {g.Count(),6}x {g.Key}");
        }
    }

    if (opts.TryGetValue("apply-type", out var atAddr) && opts.TryGetValue("type", out var atType))
    {
        var d = await ghidra.ApplyDataTypeAsync(atAddr, atType);
        Console.WriteLine($"[apply-type] {atAddr} = {d.DataType} len={d.Length} value={d.Value} (in-memory)");
    }

    if (opts.TryGetValue("run-script", out var scriptPath))
    {
        var output = await ghidra.RunScriptAsync(scriptPath);
        Console.WriteLine($"[run-script] {scriptPath}:");
        if (output.Stdout.Length > 0) Console.Write(output.Stdout);
        if (output.Stderr.Length > 0) Console.Error.Write(output.Stderr);
    }

    if (opts.TryGetValue("comments", out var comAddr))
    {
        var c = await ghidra.GetCommentsAsync(comAddr);
        Console.WriteLine($"[comments {comAddr}] eol=\"{c.Eol}\" pre=\"{c.Pre}\" post=\"{c.Post}\" plate=\"{c.Plate}\" repeatable=\"{c.Repeatable}\"");
    }

    if (opts.TryGetValue("set-comment", out var scAddr))
    {
        var type = Enum.TryParse<CommentType>(opts.GetValueOrDefault("comment-type", "Eol"), ignoreCase: true, out var t) ? t : CommentType.Eol;
        await ghidra.SetCommentAsync(scAddr, type, opts.GetValueOrDefault("comment-text", ""));
        Console.WriteLine($"[set-comment] {scAddr} {type} set (in-memory; use --save to persist)");
    }

    if (opts.TryGetValue("set-bookmark", out var sbAddr))
    {
        await ghidra.SetBookmarkAsync(sbAddr, comment: opts.GetValueOrDefault("bookmark-text", "ghidrasharp"));
        Console.WriteLine($"[set-bookmark] {sbAddr} set (in-memory; use --save to persist)");
    }

    if (opts.TryGetValue("bookmarks", out var bmAddr))
    {
        var bms = await ghidra.GetBookmarksAsync(bmAddr);
        Console.WriteLine($"[bookmarks {bmAddr}] {bms.Count}:");
        foreach (var b in bms) Console.WriteLine($"  [{b.Type}/{b.Category}] {b.Comment}");
    }

    if (opts.TryGetValue("instr-detail", out var idAddr))
    {
        var d = await ghidra.GetInstructionDetailAsync(idAddr);
        Console.WriteLine($"[instr {d.Address}] {d.Representation}  ({Convert.ToHexString(d.Bytes)})");
        foreach (var o in d.Operands)
        {
            var extra = (o.Register.Length > 0 ? $" reg={o.Register}" : "") + (o.HasScalar ? $" scalar=0x{o.Scalar:x}" : "");
            Console.WriteLine($"  op{o.Index}: {o.Representation}  [{o.Type}]{extra}");
        }
        Console.WriteLine($"  pcode ({d.Pcode.Count}):");
        foreach (var p in d.Pcode)
        {
            Console.WriteLine($"    {(p.Output.Length > 0 ? p.Output + " = " : "")}{p.Mnemonic} {string.Join(", ", p.Inputs)}");
        }
    }

    if (opts.ContainsKey("save"))
    {
        await ghidra.SaveProgramAsync();
        Console.WriteLine("[save] persisted to disk");
    }

    if (opts.ContainsKey("decompile-all"))
    {
        opts.TryGetValue("dump", out var dumpPath);
        using var dump = dumpPath is not null ? new StreamWriter(dumpPath, append: false) : null;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        int ok = 0, fail = 0;
        await foreach (var r in ghidra.DecompileManyAsync(all: true))
        {
            if (r.IsSuccess)
            {
                ok++;
                dump?.Write($">>> {r.EntryPoint}\n{r.CCode}");
            }
            else
            {
                fail++;
            }
        }
        sw.Stop();

        var perSec = (ok + fail) / Math.Max(1.0, sw.Elapsed.TotalSeconds);
        Console.WriteLine($"[batch] decompiled {ok} ok / {fail} failed in {sw.ElapsedMilliseconds} ms ({perSec:F0} func/s)");
        if (dumpPath is not null) Console.WriteLine($"[batch] dump -> {dumpPath}");
    }

    return 0;
}

static Dictionary<string, string> ParseArgs(string[] argv)
{
    var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < argv.Length; i++)
    {
        if (!argv[i].StartsWith("--", StringComparison.Ordinal)) continue;
        var key = argv[i][2..];
        var value = i + 1 < argv.Length && !argv[i + 1].StartsWith("--", StringComparison.Ordinal)
            ? argv[++i]
            : "true";
        map[key] = value;
    }
    return map;
}
