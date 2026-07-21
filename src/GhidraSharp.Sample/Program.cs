using Const24.GhidraSharp;

// Smoke / demo client for the GhidraSharp bridge — exercises most of the API.
// Run with no arguments (or --help) for the full flag reference.

var opts = ParseArgs(args);

if (args.Length == 0 || opts.ContainsKey("help"))
{
    PrintUsage();
    return 0;
}

// --batch: fan a set of binaries across a GhidraServerPool, emitting per-binary
// <name>.c + <name>.symbols.tsv + <name>.anchors.tsv. Owns its own pool; returns early.
if (opts.ContainsKey("batch"))
{
    return await RunBatch(opts);
}

var serverUrl = opts.GetValueOrDefault("server", "http://127.0.0.1:50080");

GhidraServer? spawned = null;
GhidraClient ghidra;
if (opts.ContainsKey("spawn"))
{
    spawned = await GhidraServer.StartAsync(SpawnOptions(opts));
    Console.WriteLine($"[spawn] server started on port {spawned.Port}");
    ghidra = spawned.Client;
}
else
{
    ghidra = GhidraClient.Connect(serverUrl);
}

try
{
    return await Run(ghidra, opts, serverUrl);
}
finally
{
    if (spawned is not null)
    {
        await spawned.DisposeAsync();
    }
    else
    {
        await ghidra.DisposeAsync();
    }
}

static void PrintUsage() =>
    Console.WriteLine(
        """
        GhidraSharp sample — smoke / demo client for the GhidraSharp bridge.

        Connect:   --server <url>                        (default http://127.0.0.1:50080)
                   --spawn [--serverdir <dir> | --argfile <path>] [--ghidra <install>]
        Open:      --rom <binary|domainfile> [--project <gpr>] [--lang <id>] [--writable]
                   --create-project <binary> [--proj-loc <dir>] [--proj-name <n>] [--lang <id>]
        Explore:   --list [--calls <fn>] | --memory-blocks|--sections | --symbols | --symbols-at <a>
                   --find-string "<text>" | --xrefs <a> | --function <a> | --data <a> | --datatypes [<f>]
                   --bytes <a> [--len N] | --disasm <a> [--count N] | --instr-detail <a>
                   --comments <a> | --bookmarks <a>
        Decompile: --addr <a> | --name <fn> [--context] | --decompile-all [--dump <file>]
        Mutate:    --rename-at <a> --to <name> | --apply-type <a> --type <t> | --save
                   --set-comment <a> [--comment-type <t>] [--comment-text <s>]
                   --set-bookmark <a> [--bookmark-text <s>]
        Scripts:   --run-script <path>
        Batch:     --batch --paths <file|dir> [--out <dir>] [--pool N]
                   (a directory picks up *.dll and *.exe only; a file lists one path per line)

        --spawn starts (and stops) its own Java server; otherwise it connects to --server.
        """);

// --serverdir launches an unzipped release dist; otherwise --argfile launches a source build.
static GhidraServerOptions SpawnOptions(Dictionary<string, string> opts) =>
    opts.TryGetValue("serverdir", out var serverDir)
        ? new GhidraServerOptions { ServerDirectory = serverDir, GhidraInstallDir = opts.GetValueOrDefault("ghidra") }
        : new GhidraServerOptions { ArgFile = opts.GetValueOrDefault("argfile", "server/build/ghidrasharp-java.args"), GhidraInstallDir = opts.GetValueOrDefault("ghidra") };

static async Task<int> RunBatch(Dictionary<string, string> opts)
{
    var listArg = opts.GetValueOrDefault("paths", "");
    if (listArg.Length == 0)
    {
        Console.Error.WriteLine("--batch needs --paths <file-with-one-path-per-line | directory>");
        return 2;
    }
    var discovered = Directory.Exists(listArg)
        ? Directory.EnumerateFiles(listArg, "*.dll").Concat(Directory.EnumerateFiles(listArg, "*.exe"))
        : File.ReadAllLines(listArg).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#'));
    var paths = discovered.ToList();
    var outDir = opts.GetValueOrDefault("out", "batch-out");
    var poolN = int.TryParse(opts.GetValueOrDefault("pool", "4"), out var n) ? n : 4;

    Console.Error.WriteLine($"[batch] {paths.Count} binaries · pool={poolN} · out={outDir}");
    await using var pool = await GhidraServerPool.StartAsync(poolN, SpawnOptions(opts));
    var progress = new Progress<PoolProgress>(p => Console.Error.WriteLine($"[batch] {p.Done}/{p.Total} done · {p.Failed} failed"));
    var results = await BatchExtractor.RunAsync(pool, paths, outDir, progress: progress);

    Console.WriteLine("name\tlang\tfunctions\tdecompiled\tsymbols\tanchors\terror");
    foreach (var r in results)
    {
        Console.WriteLine($"{r.Name}\t{r.LanguageId}\t{r.FunctionCount}\t{r.DecompiledOk}\t{r.SymbolCount}\t{r.AnchorHits}\t{r.Error}");
    }

    Console.Error.WriteLine($"[batch] complete · {results.Count(r => r.Error is null)}/{results.Count} ok");
    return 0;
}

static async Task<int> Run(GhidraClient ghidra, Dictionary<string, string> opts, string serverUrl)
{
    try
    {
        var info = await ghidra.PingAsync();
        Console.WriteLine($"[ping] server up — Ghidra {info.GhidraVersion}, server {info.ServerVersion}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[ping] could not reach server at {serverUrl}: {ex.Message}");
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

        // --context: show the function's immediate call-neighbourhood in one shot
        // (callers + callees), so an agent sees the pak-read -> decrypt -> send path
        // without three extra round trips.
        if (opts.ContainsKey("context"))
        {
            var fd = name.Length > 0
                ? await ghidra.GetFunctionByNameAsync(name, includeCallers: true)
                : await ghidra.GetFunctionAtAsync(addr, includeCallers: true);
            Console.WriteLine($"[context] callers ({fd.Callers.Count}): {string.Join(", ", fd.Callers.Take(12))}");
            var frefs = await ghidra.GetFunctionReferencesAsync(fd.EntryPoint);
            var callees = frefs.Where(r => r.IsCall).Select(r => r.ToAddress).Distinct().Take(12).ToList();
            Console.WriteLine($"[context] callees ({callees.Count}): {string.Join(", ", callees)}");
        }
    }

    // --find-string "<substr>": concept -> code. Ghidra auto-labels defined strings
    // as s_<text>_<addr> (u_ for unicode); filter those by substring, then xref each
    // so you jump straight to the functions that CONSUME the string. This is the
    // single most-used RE loop (an agent knows "pak"/"key", not an address).
    if (opts.TryGetValue("find-string", out var findStr))
    {
        var found = await ghidra.FindStringsAsync(findStr);
        Console.WriteLine($"[find-string \"{findStr}\"] {found.Count} string(s) — concept -> code:");
        foreach (var f in found)
        {
            Console.WriteLine($"  {f.Address}  {(f.IsUnicode ? "u" : "s")}: {f.Text}");
            if (f.XrefFrom.Count > 0)
            {
                Console.WriteLine($"     xref-from: {string.Join(", ", f.XrefFrom.Take(8))}  ({f.XrefFrom.Count} sites)");
            }
        }
    }

    // --memory-blocks / --sections: the section layout (name, range, size, perms). A tiny
    // .text next to a huge .rsrc/.data means the binary is mostly DATA, not code.
    if (opts.ContainsKey("memory-blocks") || opts.ContainsKey("sections"))
    {
        var blocks = await ghidra.ListMemoryBlocksAsync();
        Console.WriteLine($"[memory-blocks] {blocks.Count} block(s):");
        foreach (var b in blocks)
        {
            var perm = $"{(b.Read ? "r" : "-")}{(b.Write ? "w" : "-")}{(b.Execute ? "x" : "-")}";
            Console.WriteLine($"  {b.Name,-16} {b.Start}-{b.End}  {b.Size,10} B  {perm}  {(b.Initialized ? "init" : "uninit")}");
        }
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
            foreach (var f in callers.Take(10))
            {
                Console.WriteLine($"  {f.EntryPoint}  {f.Name}");
            }
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
        foreach (var s in at)
        {
            Console.WriteLine($"  {s.Name}  [{s.SymbolType}, {s.Source}{(s.IsPrimary ? ", primary" : "")}]");
        }
    }

    if (opts.TryGetValue("rename-at", out var renAddr) && opts.TryGetValue("to", out var newName))
    {
        var before = await ghidra.GetSymbolsAtAsync(renAddr);
        Console.WriteLine($"[rename] {renAddr}: \"{(before.Count > 0 ? before[0].Name : null)}\" -> \"{newName}\"");
        await ghidra.RenameSymbolAtAsync(renAddr, newName);
        var after = await ghidra.GetSymbolsAtAsync(renAddr);
        Console.WriteLine($"[rename] now: \"{(after.Count > 0 ? after[0].Name : null)}\" (in-memory; not saved)");
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
        if (output.Stdout.Length > 0)
        {
            Console.Write(output.Stdout);
        }

        if (output.Stderr.Length > 0)
        {
            Console.Error.Write(output.Stderr);
        }
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
        foreach (var b in bms)
        {
            Console.WriteLine($"  [{b.Type}/{b.Category}] {b.Comment}");
        }
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
        if (dumpPath is not null)
        {
            Console.WriteLine($"[batch] dump -> {dumpPath}");
        }
    }

    return 0;
}

static Dictionary<string, string> ParseArgs(string[] argv)
{
    var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < argv.Length; i++)
    {
        if (!argv[i].StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var key = argv[i][2..];
        var value = i + 1 < argv.Length && !argv[i + 1].StartsWith("--", StringComparison.Ordinal)
            ? argv[++i]
            : "true";
        map[key] = value;
    }
    return map;
}
