using Const24.GhidraSharp;

// Minimal smoke client for the GhidraSharp bridge.
//
//   GhidraSharp.Sample [--server http://127.0.0.1:50080]
//                      [--rom <path-or-domainfile>] [--lang <languageId>]
//                      [--addr 0x21e0 | --name FUN_000021e0]
//
// With no --rom it just pings the server. With --rom it opens the program and,
// if --addr/--name is given, decompiles that function.

var opts = ParseArgs(args);
var server = opts.GetValueOrDefault("server", "http://127.0.0.1:50080");

await using var ghidra = GhidraClient.Connect(server);

try
{
    var pong = await ghidra.PingAsync("hello from C#");
    Console.WriteLine($"[ping] server up, Ghidra {pong.GhidraVersion}: \"{pong.Message}\"");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ping] could not reach server at {server}: {ex.Message}");
    return 1;
}

if (opts.TryGetValue("rom", out var rom))
{
    var open = await ghidra.OpenProgramAsync(
        rom,
        projectPath: opts.GetValueOrDefault("project", ""),
        languageId: opts.GetValueOrDefault("lang", ""));

    if (!open.Success)
    {
        Console.Error.WriteLine($"[open] failed: {open.Error}");
        return 2;
    }

    Console.WriteLine(
        $"[open] {open.ProgramName} ({open.LanguageId}) base=0x{open.ImageBase:x} functions={open.FunctionCount}");

    var addr = opts.GetValueOrDefault("addr", "");
    var name = opts.GetValueOrDefault("name", "");
    if (addr.Length > 0 || name.Length > 0)
    {
        var dec = addr.Length > 0
            ? await ghidra.DecompileAtAsync(addr)
            : await ghidra.DecompileByNameAsync(name);

        if (!dec.Success)
        {
            Console.Error.WriteLine($"[decompile] failed: {dec.Error}");
            return 3;
        }

        Console.WriteLine($"[decompile] {dec.Signature}  @ {dec.EntryAddress}");
        Console.WriteLine(dec.CCode);
    }

    if (opts.ContainsKey("list"))
    {
        var funcs = await ghidra.ListFunctionsAsync(includeCalls: true);
        Console.WriteLine($"[list] {funcs.Count} functions");

        // The whole point of the migration: query the program with LINQ.
        var biggest = funcs
            .OrderByDescending(f => f.Size)
            .Take(5)
            .Select(f => $"  {f.EntryAddress}  {f.Size,6}b  {f.ParameterCount}p  {f.Name}");
        Console.WriteLine("[linq] 5 largest functions:");
        foreach (var line in biggest) Console.WriteLine(line);

        var hubs = funcs.Where(f => f.Calls.Count >= 10).Count();
        Console.WriteLine($"[linq] functions that call >=10 others: {hubs}");

        if (opts.TryGetValue("calls", out var callee))
        {
            var callers = funcs
                .Where(f => f.Calls.Contains(callee))
                .OrderBy(f => f.Name)
                .ToList();
            Console.WriteLine($"[linq] {callers.Count} functions call \"{callee}\":");
            foreach (var f in callers.Take(10)) Console.WriteLine($"  {f.EntryAddress}  {f.Name}");
        }
    }
}

return 0;

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
