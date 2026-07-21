using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Const24.GhidraSharp;

/// <summary>
/// One binary's outcome from a <see cref="BatchExtractor"/> run.
/// </summary>
/// <param name="Path">The source binary path.</param>
/// <param name="Name">The binary's file name (used as the output-file stem).</param>
/// <param name="LanguageId">Ghidra language id detected on import (empty on failure).</param>
/// <param name="FunctionCount">Number of functions Ghidra defined.</param>
/// <param name="DecompiledOk">Functions decompiled successfully.</param>
/// <param name="DecompiledFailed">Functions whose decompilation failed.</param>
/// <param name="SymbolCount">Symbols written to <c>&lt;name&gt;.symbols.tsv</c>.</param>
/// <param name="AnchorHits">Anchor-API call sites written to <c>&lt;name&gt;.anchors.tsv</c>.</param>
/// <param name="Error">Failure message, or <c>null</c> on success.</param>
public sealed record BinaryExtractSummary(
    string Path,
    string Name,
    string LanguageId,
    int FunctionCount,
    int DecompiledOk,
    int DecompiledFailed,
    int SymbolCount,
    int AnchorHits,
    string? Error);

/// <summary>
/// Options controlling what <see cref="BatchExtractor"/> emits per binary.
/// </summary>
public sealed record BatchExtractorOptions
{
    /// <summary>Emit a whole-binary C decompile to <c>&lt;name&gt;.c</c>.</summary>
    public bool Decompile { get; init; } = true;

    /// <summary>Emit the symbol table to <c>&lt;name&gt;.symbols.tsv</c> (the naming oracle: address → name → type → source).</summary>
    public bool Symbols { get; init; } = true;

    /// <summary>
    /// Emit mechanical data-path coverage to <c>&lt;name&gt;.anchors.tsv</c>: for every symbol whose name contains an
    /// entry of <see cref="AnchorApis"/>, list each referencing call site and the function that contains it. This is a
    /// deterministic "did I find every data-path function?" check that does not depend on a model's judgement.
    /// </summary>
    public bool AnchorCoverage { get; init; } = true;

    /// <summary>Per-function decompiler timeout in seconds (0 = server default).</summary>
    public int DecompileTimeoutSeconds { get; init; }

    /// <summary>
    /// API-name fragments that mark a data path (file I/O, crypto, registry, sockets, J2534). A symbol counts as an
    /// anchor when its name contains any of these (case-insensitive).
    /// </summary>
    public IReadOnlyCollection<string> AnchorApis { get; init; } = DefaultAnchorApis;

    /// <summary>The default anchor-API set: file I/O + WinCrypt + registry + sockets + J2534 PassThru.</summary>
    public static readonly IReadOnlyCollection<string> DefaultAnchorApis =
    [
        "CreateFile", "ReadFile", "WriteFile", "fopen", "fread", "fwrite", "_read", "MapViewOfFile", "GetModuleFileName",
        "CryptDecrypt", "CryptEncrypt", "CryptDeriveKey", "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
        "CryptImportKey", "CryptGenKey", "CryptGenRandom",
        "RegOpenKey", "RegQueryValue", "RegCreateKey", "RegSetValue",
        "socket", "connect", "send", "recv", "WSAStartup",
        "PassThru",
    ];
}

/// <summary>
/// Batch reverse-engineering extractor: runs a set of binaries through a <see cref="GhidraServerPool"/> (process-level
/// parallelism) and, per binary, writes a whole-binary C decompile, a symbol-table TSV (the authors' own names — a
/// naming oracle for non-stripped MFC/C++ images), and a mechanical anchor-API call-site coverage TSV. Generic across
/// architectures; the anchor set defaults to Windows data-path APIs and is overridable.
/// </summary>
public static class BatchExtractor
{
    /// <summary>
    /// Extract every binary in <paramref name="binaryPaths"/> into <paramref name="outDir"/>, distributing the work
    /// across <paramref name="pool"/>. Each binary is imported+analyzed on one pooled server, its artifacts written,
    /// then its program is closed so the server can take the next. Per-binary failures are captured in the returned
    /// summary (never abort the batch).
    /// </summary>
    /// <param name="pool">The server pool to run on (caller owns and disposes it).</param>
    /// <param name="binaryPaths">The binaries to process.</param>
    /// <param name="outDir">Output directory (created if missing); files are <c>&lt;name&gt;.c</c> / <c>.symbols.tsv</c> / <c>.anchors.tsv</c>.</param>
    /// <param name="options">What to emit; defaults to all three artifacts and the default anchor set.</param>
    /// <param name="progress">Optional progress reporter, fired as each binary completes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>One <see cref="BinaryExtractSummary"/> per input path, in input order.</returns>
    public static async Task<IReadOnlyList<BinaryExtractSummary>> RunAsync(
        GhidraServerPool pool,
        IEnumerable<string> binaryPaths,
        string outDir,
        BatchExtractorOptions? options = null,
        IProgress<PoolProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(binaryPaths);
        ArgumentException.ThrowIfNullOrWhiteSpace(outDir);
        options ??= new BatchExtractorOptions();
        Directory.CreateDirectory(outDir);

        var paths = binaryPaths as IReadOnlyList<string> ?? [.. binaryPaths];

        // Output stems: a unique basename keeps its name; a basename shared by 2+ inputs
        // (routine when sweeping per-model / per-version folders) gets a short path-hash
        // suffix, so same-named binaries from different folders don't overwrite each other's
        // <name>.c / .symbols.tsv / .anchors.tsv.
        var basenameCounts = paths
            .GroupBy(p => Path.GetFileName(p), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        string StemFor(string p)
        {
            var b = Path.GetFileName(p);
            return basenameCounts[b] > 1 ? $"{b}_{ShortHash(p)}" : b;
        }

        var byIndex = new BinaryExtractSummary?[paths.Count];
        var results = await pool.ForEachAsync(
            Enumerable.Range(0, paths.Count),
            async (client, idx, token) => byIndex[idx] = await ExtractOneAsync(client, paths[idx], StemFor(paths[idx]), outDir, options, token),
            progress,
            ct).ConfigureAwait(false);

        // A binary whose body threw has no summary of its own — build one from the pool's
        // recorded error (the pool has already restarted the slot and retried once if the
        // server process died; only an unhealable failure lands here).
        return [.. results.Select((r, i) =>
            byIndex[i] ?? new BinaryExtractSummary(
                paths[i], StemFor(paths[i]), "", 0, 0, 0, 0, 0, r.Error?.Message ?? "no result"))];
    }

    // Exceptions escape deliberately: the pool needs to see them to detect a dead server
    // and restart the slot; RunAsync maps them into failure summaries afterwards.
    private static async Task<BinaryExtractSummary> ExtractOneAsync(
        GhidraClient client, string path, string name, string outDir, BatchExtractorOptions options, CancellationToken ct)
    {
        try
        {
            var info = await client.OpenProgramAsync(path, analyze: true, ct: ct).ConfigureAwait(false);
            var funcs = await client.ListFunctionsAsync(includeCalls: false, ct).ConfigureAwait(false);

            // Symbols are needed for both the oracle and the anchor scan — fetch once.
            var syms = options.Symbols || options.AnchorCoverage
                ? await client.ListSymbolsAsync(includeDynamic: false, ct: ct).ConfigureAwait(false)
                : [];

            if (options.Symbols)
            {
                var sb = new StringBuilder("address\tname\ttype\tsource\n");
                foreach (var s in syms)
                {
                    sb.Append(s.Address).Append('\t').Append(s.Name).Append('\t').Append(s.SymbolType).Append('\t').Append(s.Source).Append('\n');
                }

                await File.WriteAllTextAsync(Path.Combine(outDir, name + ".symbols.tsv"), sb.ToString(), ct).ConfigureAwait(false);
            }

            var okc = 0;
            var failc = 0;
            if (options.Decompile)
            {
                var sb = new StringBuilder();
                sb.Append("// ").Append(name).Append(" (").Append(info.LanguageId)
                  .Append(") base=0x").Append(info.ImageBase.ToString("x", CultureInfo.InvariantCulture))
                  .Append(" functions=").Append(info.FunctionCount).Append('\n').Append('\n');
                await foreach (var d in client.DecompileManyAsync(all: true, timeoutSeconds: options.DecompileTimeoutSeconds, ct: ct).ConfigureAwait(false))
                {
                    if (d.IsSuccess)
                    {
                        sb.Append("// -- fn @").Append(d.EntryPoint).Append("  ").Append(d.Signature).Append(" --\n")
                          .Append(d.CCode.TrimEnd()).Append('\n').Append('\n');
                        okc++;
                    }
                    else
                    {
                        failc++;
                    }
                }
                await File.WriteAllTextAsync(Path.Combine(outDir, name + ".c"), sb.ToString(), ct).ConfigureAwait(false);
            }

            var anchorHits = 0;
            if (options.AnchorCoverage)
            {
                var ordered = funcs
                    .Select(f => (Entry: ParseHex(f.EntryPoint), f.Name, f.Size))
                    .Where(t => t.Entry.HasValue)
                    .Select(t => (Entry: t.Entry!.Value, t.Name, t.Size))
                    .OrderBy(t => t.Entry)
                    .ToList();

                var sb = new StringBuilder("api\tapi_addr\tcall_site\tcontaining_fn\n");
                foreach (var s in syms)
                {
                    if (!options.AnchorApis.Any(a => s.Name.Contains(a, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    IReadOnlyList<GhidraReference> refs;
                    // Some symbols (e.g. externals) carry addresses the reference query rejects —
                    // skip those; transport failures (inner RpcException) escape to the pool.
                    try { refs = await client.GetReferencesToAsync(s.Address, ct).ConfigureAwait(false); }
                    catch (GhidraException ex) when (ex.InnerException is not Grpc.Core.RpcException) { continue; }
                    foreach (var r in refs)
                    {
                        var from = ParseHex(r.FromAddress);
                        sb.Append(s.Name).Append('\t').Append(s.Address).Append('\t').Append(r.FromAddress).Append('\t')
                          .Append(from.HasValue ? ContainingFunction(ordered, from.Value) : "").Append('\n');
                        anchorHits++;
                    }
                }
                await File.WriteAllTextAsync(Path.Combine(outDir, name + ".anchors.tsv"), sb.ToString(), ct).ConfigureAwait(false);
            }

            return new BinaryExtractSummary(path, name, info.LanguageId, info.FunctionCount, okc, failc, syms.Count, anchorHits, null);
        }
        finally
        {
            // Fresh bounded token: the batch's own token is typically already cancelled
            // when cleanup runs, and the close is what releases the program's on-disk lock.
            using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try { await client.CloseProgramAsync(closeCts.Token).ConfigureAwait(false); } catch { /* best effort */ }
        }
    }

    private static string ContainingFunction(List<(ulong Entry, string Name, ulong Size)> ordered, ulong addr)
    {
        // ordered ascending by Entry, bodies assumed non-overlapping: the candidate is the
        // function with the greatest Entry <= addr — it either covers addr or nothing does.
        int lo = 0, hi = ordered.Count - 1, candidate = -1;
        while (lo <= hi)
        {
            var mid = lo + ((hi - lo) >> 1);
            if (ordered[mid].Entry <= addr)
            {
                candidate = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }
        if (candidate < 0)
        {
            return "";
        }
        var (entry, name, size) = ordered[candidate];
        return addr < entry + size ? name : "";
    }

    private static string ShortHash(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..8].ToLowerInvariant();

    private static ulong? ParseHex(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return null;
        }

        var h = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s.AsSpan(2) : s.AsSpan();
        return ulong.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
    }
}
