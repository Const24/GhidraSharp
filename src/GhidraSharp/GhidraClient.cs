using System.Runtime.CompilerServices;
using Grpc.Core;
using Grpc.Net.Client;
using Const24.GhidraSharp.Protocol;
using ProtoSvc = Const24.GhidraSharp.Protocol.GhidraSharpService;

namespace Const24.GhidraSharp;

/// <summary>
/// Typed C# entry point to a running <c>GhidraSharpServer</c> (Ghidra running as a
/// library) over gRPC. Methods are intent-named and return documented result
/// records; the gRPC wire types never surface.
/// </summary>
/// <remarks>
/// One <see cref="GhidraClient"/> owns one channel; create it once and reuse it.
/// The server holds a single "current program" — call
/// <see cref="OpenProgramAsync"/> before decompiling or querying references.
/// For driving a server you also start/stop yourself, see <see cref="GhidraServer"/>.
/// </remarks>
public sealed class GhidraClient : IAsyncDisposable, IDisposable
{
    private readonly GrpcChannel _channel;
    private readonly ProtoSvc.GhidraSharpServiceClient _client;

    private GhidraClient(GrpcChannel channel)
    {
        _channel = channel;
        _client = new ProtoSvc.GhidraSharpServiceClient(channel);
    }

    /// <summary>Connect to a server listening at <paramref name="address"/> (e.g. <c>http://127.0.0.1:50080</c>).</summary>
    /// <param name="address">The server's HTTP/2 base address.</param>
    public static GhidraClient Connect(string address)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return new GhidraClient(GrpcChannel.ForAddress(address));
    }

    /// <summary>Connect using an already-configured channel (custom credentials, handler, etc.).</summary>
    /// <param name="channel">A configured gRPC channel pointing at the server.</param>
    public static GhidraClient FromChannel(GrpcChannel channel)
        => new(channel ?? throw new ArgumentNullException(nameof(channel)));

    /// <summary>Liveness check; returns the Ghidra version the server is running.</summary>
    /// <param name="ct">Cancellation token.</param>
    public async Task<ServerInfo> PingAsync(CancellationToken ct = default)
    {
        var reply = await _client.PingAsync(new PingRequest { Message = "ping" }, cancellationToken: ct);
        return new ServerInfo { GhidraVersion = reply.GhidraVersion };
    }

    /// <summary>
    /// Open a program and make it the server's current program. Opens an existing
    /// Ghidra project program when <paramref name="projectPath"/> is given,
    /// otherwise imports the binary at <paramref name="programPath"/>.
    /// </summary>
    /// <param name="programPath">A binary file to import, or a program name inside the project.</param>
    /// <param name="projectPath">A Ghidra project (<c>.gpr</c>/<c>.rep</c> or its folder); empty to import a binary into a scratch project.</param>
    /// <param name="languageId">Language/compiler-spec id to use when importing a raw binary (ignored when opening an existing program).</param>
    /// <param name="analyze">Run auto-analysis after importing a binary.</param>
    /// <param name="writable">Open the program for modification (required for renaming). Default is read-only, leaving the source project untouched; changes are never auto-saved.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">The server could not open the program.</exception>
    public async Task<ProgramInfo> OpenProgramAsync(
        string programPath,
        string projectPath = "",
        string languageId = "",
        bool analyze = true,
        bool writable = false,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(programPath);
        var reply = await _client.OpenProgramAsync(
            new OpenProgramRequest
            {
                ProgramPath = programPath,
                ProjectPath = projectPath,
                LanguageId = languageId,
                Analyze = analyze,
                Writable = writable,
            },
            cancellationToken: ct);

        if (!reply.Success)
        {
            throw new GhidraException($"OpenProgram failed: {reply.Error}");
        }

        return new ProgramInfo
        {
            Name = reply.ProgramName,
            LanguageId = reply.LanguageId,
            ImageBase = reply.ImageBase,
            FunctionCount = (int)reply.FunctionCount,
        };
    }

    /// <summary>Decompile the function whose entry point is <paramref name="address"/> (hex, e.g. <c>0x21e0</c>).</summary>
    /// <param name="address">Entry-point address of the function.</param>
    /// <param name="timeoutSeconds">Decompiler timeout; 0 uses the server default.</param>
    /// <param name="ct">Cancellation token.</param>
    public Task<Decompilation> DecompileAtAsync(string address, int timeoutSeconds = 0, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return DecompileAsync(new DecompileRequest { Address = address, TimeoutSeconds = timeoutSeconds }, ct);
    }

    /// <summary>Decompile the function named <paramref name="name"/>.</summary>
    /// <param name="name">Function name (e.g. <c>FUN_000021e0</c> or a user-applied name).</param>
    /// <param name="timeoutSeconds">Decompiler timeout; 0 uses the server default.</param>
    /// <param name="ct">Cancellation token.</param>
    public Task<Decompilation> DecompileByNameAsync(string name, int timeoutSeconds = 0, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return DecompileAsync(new DecompileRequest { Name = name, TimeoutSeconds = timeoutSeconds }, ct);
    }

    private async Task<Decompilation> DecompileAsync(DecompileRequest request, CancellationToken ct)
        => ToDecompilation(await _client.DecompileFunctionAsync(request, cancellationToken: ct));

    /// <summary>
    /// List the functions in the current program. The result is a plain list,
    /// ready to query with LINQ (e.g. <c>funcs.Where(f =&gt; f.Calls.Contains("..."))</c>).
    /// </summary>
    /// <param name="includeCalls">Populate each function's <see cref="GhidraFunction.Calls"/> (its callees); costs an extra pass server-side.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open.</exception>
    public async Task<IReadOnlyList<GhidraFunction>> ListFunctionsAsync(bool includeCalls = false, CancellationToken ct = default)
    {
        var reply = await _client.ListFunctionsAsync(
            new ListFunctionsRequest { IncludeCalls = includeCalls }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"ListFunctions failed: {reply.Error}");
        }
        return reply.Functions.Select(ToFunction).ToList();
    }

    /// <summary>
    /// Batch decompile, streamed: one round trip, results arrive as they are
    /// produced server-side. Pass <paramref name="all"/> to sweep the whole
    /// program, or specific entry <paramref name="addresses"/> (hex).
    /// </summary>
    /// <param name="addresses">Entry addresses to decompile (ignored when <paramref name="all"/> is true).</param>
    /// <param name="all">Decompile every function in the program.</param>
    /// <param name="timeoutSeconds">Per-function decompiler timeout (0 = server default).</param>
    /// <param name="ct">Cancellation token.</param>
    public async IAsyncEnumerable<Decompilation> DecompileManyAsync(
        IEnumerable<string>? addresses = null,
        bool all = false,
        int timeoutSeconds = 0,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var request = new DecompileFunctionsRequest { All = all, TimeoutSeconds = timeoutSeconds };
        if (addresses is not null)
        {
            request.Addresses.AddRange(addresses);
        }

        using var call = _client.DecompileFunctions(request, cancellationToken: ct);
        await foreach (var reply in call.ResponseStream.ReadAllAsync(ct))
        {
            yield return ToDecompilation(reply);
        }
    }

    /// <summary>
    /// References (xrefs) whose target is <paramref name="address"/> — "who points
    /// here" (callers, jumps into, data reads of that address).
    /// </summary>
    /// <param name="address">The target address (hex).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<IReadOnlyList<GhidraReference>> GetReferencesToAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetReferencesToAsync(new ReferencesRequest { Address = address }, cancellationToken: ct);
        return ToReferences(reply);
    }

    /// <summary>
    /// References (xrefs) originating from <paramref name="address"/> — "what this
    /// points to" (the calls, jumps and data accesses made at that address).
    /// </summary>
    /// <param name="address">The source address (hex).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<IReadOnlyList<GhidraReference>> GetReferencesFromAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetReferencesFromAsync(new ReferencesRequest { Address = address }, cancellationToken: ct);
        return ToReferences(reply);
    }

    /// <summary>
    /// List symbols (names) in the program. By default only "real" symbols are
    /// returned; pass <paramref name="includeDynamic"/> to include Ghidra's
    /// auto-generated ones (<c>FUN_*</c>, <c>DAT_*</c>, <c>LAB_*</c>).
    /// </summary>
    /// <param name="includeDynamic">Include auto-generated (dynamic) symbols.</param>
    /// <param name="name">If given, return only symbols with this exact name.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open.</exception>
    public async Task<IReadOnlyList<GhidraSymbol>> ListSymbolsAsync(
        bool includeDynamic = false, string? name = null, CancellationToken ct = default)
    {
        var reply = await _client.ListSymbolsAsync(
            new ListSymbolsRequest { IncludeDynamic = includeDynamic, Name = name ?? "" }, cancellationToken: ct);
        return ToSymbols(reply);
    }

    /// <summary>Symbols defined at <paramref name="address"/> (hex).</summary>
    /// <param name="address">The address to look up.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<IReadOnlyList<GhidraSymbol>> GetSymbolsAtAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetSymbolsAtAsync(new SymbolsAtRequest { Address = address }, cancellationToken: ct);
        return ToSymbols(reply);
    }

    /// <summary>
    /// Rename the primary symbol at <paramref name="address"/>. The program must
    /// have been opened with <c>writable: true</c>; the change is in-memory and is
    /// not persisted unless the program is later saved.
    /// </summary>
    /// <param name="address">Address of the symbol to rename (hex).</param>
    /// <param name="newName">The new name.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No symbol at the address, the program is read-only, or the name is invalid.</exception>
    public Task RenameSymbolAtAsync(string address, string newName, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);
        return RenameAsync(new RenameSymbolRequest { Address = address, NewName = newName }, ct);
    }

    /// <summary>
    /// Rename the symbol currently named <paramref name="oldName"/>. The program
    /// must have been opened with <c>writable: true</c>; the change is in-memory.
    /// </summary>
    /// <param name="oldName">Current name of the symbol.</param>
    /// <param name="newName">The new name.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No such symbol, the program is read-only, or the name is invalid.</exception>
    public Task RenameSymbolByNameAsync(string oldName, string newName, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oldName);
        ArgumentException.ThrowIfNullOrWhiteSpace(newName);
        return RenameAsync(new RenameSymbolRequest { OldName = oldName, NewName = newName }, ct);
    }

    private async Task RenameAsync(RenameSymbolRequest request, CancellationToken ct)
    {
        var reply = await _client.RenameSymbolAsync(request, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"RenameSymbol failed: {reply.Error}");
        }
    }

    private static IReadOnlyList<GhidraSymbol> ToSymbols(ListSymbolsReply reply)
    {
        if (!reply.Success)
        {
            throw new GhidraException($"Symbols query failed: {reply.Error}");
        }
        return reply.Symbols.Select(s => new GhidraSymbol
        {
            Name = s.Name,
            Address = s.Address,
            SymbolType = s.SymbolType,
            Source = s.Source,
            IsPrimary = s.IsPrimary,
            IsGlobal = s.IsGlobal,
        }).ToList();
    }

    private static GhidraFunction ToFunction(FunctionInfo f) => new()
    {
        Name = f.Name,
        EntryPoint = f.EntryAddress,
        Size = f.Size,
        ParameterCount = f.ParameterCount,
        IsThunk = f.IsThunk,
        Calls = f.Calls.ToList(),
    };

    private static Decompilation ToDecompilation(DecompileReply r) => new()
    {
        IsSuccess = r.Success,
        EntryPoint = r.EntryAddress,
        Signature = r.Signature,
        CCode = r.CCode,
        Error = r.Error,
    };

    private static IReadOnlyList<GhidraReference> ToReferences(ReferencesReply reply)
    {
        if (!reply.Success)
        {
            throw new GhidraException($"GetReferences failed: {reply.Error}");
        }
        return reply.References.Select(r => new GhidraReference
        {
            FromAddress = r.FromAddress,
            ToAddress = r.ToAddress,
            ReferenceType = r.ReferenceType,
            IsCall = r.IsCall,
            IsJump = r.IsJump,
            IsData = r.IsData,
            OperandIndex = r.OperandIndex,
            IsPrimary = r.IsPrimary,
        }).ToList();
    }

    /// <inheritdoc/>
    public void Dispose() => _channel.Dispose();

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        _channel.Dispose();
        return ValueTask.CompletedTask;
    }
}
