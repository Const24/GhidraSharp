using System.Runtime.CompilerServices;
using Grpc.Core;
using Grpc.Core.Interceptors;
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
/// <para>
/// This client needs a running <c>GhidraSharpServer</c>: download
/// <c>ghidrasharp-server</c> from https://github.com/Const24/GhidraSharp/releases
/// and run it, then <see cref="Connect"/> to it — or let <see cref="GhidraServer"/>
/// spawn and own one for you.
/// </para>
/// </remarks>
public sealed class GhidraClient : IAsyncDisposable, IDisposable
{
    // List replies (functions/symbols/data types) put the whole result in one
    // message; the default 4 MB receive cap can be exceeded on a large program.
    private const int MaxMessageBytes = 256 * 1024 * 1024;

    private readonly GrpcChannel _channel;
    private readonly ProtoSvc.GhidraSharpServiceClient _client;

    private GhidraClient(GrpcChannel channel)
    {
        _channel = channel;
        var invoker = channel.Intercept(new ServerUnavailableInterceptor());
        _client = new ProtoSvc.GhidraSharpServiceClient(invoker);
    }

    /// <summary>Connect to a server listening at <paramref name="address"/> (e.g. <c>http://127.0.0.1:50080</c>).</summary>
    /// <param name="address">The server's HTTP/2 base address.</param>
    public static GhidraClient Connect(string address)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var options = new GrpcChannelOptions { MaxReceiveMessageSize = MaxMessageBytes };
        return new GhidraClient(GrpcChannel.ForAddress(address, options));
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

    /// <summary>List the processor languages Ghidra supports — its language picker. Use a returned
    /// <see cref="GhidraLanguage.Id"/> as the languageId when importing a raw (headerless) binary.</summary>
    /// <param name="nameContains">Optional case-insensitive filter over id / processor / description.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">The server reported a failure.</exception>
    public async Task<IReadOnlyList<GhidraLanguage>> ListLanguagesAsync(string nameContains = "", CancellationToken ct = default)
    {
        var reply = await _client.ListLanguagesAsync(
            new ListLanguagesRequest { NameContains = nameContains ?? "" }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"ListLanguages failed: {reply.Error}");
        }
        return ToLanguages(reply);
    }

    private static List<GhidraLanguage> ToLanguages(ListLanguagesReply reply)
    {
        var list = new List<GhidraLanguage>(reply.Languages.Count);
        foreach (var l in reply.Languages)
        {
            list.Add(new GhidraLanguage
            {
                Id = l.Id,
                Processor = l.Processor,
                Endian = l.Endian,
                Size = l.Size,
                Variant = l.Variant,
                Description = l.Description,
            });
        }
        return list;
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

        return ToProgramInfo(reply);
    }

    /// <summary>
    /// Import a binary into a new persistent Ghidra project on disk, analyze it,
    /// save it, and make it the current program. Reopen later with
    /// <see cref="OpenProgramAsync"/> pointed at the project.
    /// </summary>
    /// <param name="binaryPath">The binary to import.</param>
    /// <param name="projectLocation">An existing directory to create the project in.</param>
    /// <param name="projectName">Project name; produces <c>&lt;location&gt;/&lt;name&gt;.gpr</c> + <c>.rep</c>.</param>
    /// <param name="languageId">Optional language/compiler-spec id for headerless binaries.</param>
    /// <param name="analyze">Run auto-analysis before saving.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">The binary is missing, the project exists, or import failed.</exception>
    public async Task<ProgramInfo> CreateProjectAsync(
        string binaryPath,
        string projectLocation,
        string projectName,
        string languageId = "",
        bool analyze = true,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(binaryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(projectLocation);
        ArgumentException.ThrowIfNullOrWhiteSpace(projectName);
        var reply = await _client.CreateProjectAsync(
            new CreateProjectRequest
            {
                BinaryPath = binaryPath,
                ProjectLocation = projectLocation,
                ProjectName = projectName,
                LanguageId = languageId,
                Analyze = analyze,
            },
            cancellationToken: ct);

        if (!reply.Success)
        {
            throw new GhidraException($"CreateProject failed: {reply.Error}");
        }
        return ToProgramInfo(reply);
    }

    /// <summary>
    /// Persist the current program's changes to disk. The program must have been
    /// opened writable and be backed by a project (e.g. from
    /// <see cref="CreateProjectAsync"/> or an <see cref="OpenProgramAsync"/> with
    /// <c>writable: true</c>); a transiently imported program cannot be saved.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or it is not backed by a project.</exception>
    public async Task SaveProgramAsync(CancellationToken ct = default)
    {
        var reply = await _client.SaveProgramAsync(new SaveProgramRequest(), cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"SaveProgram failed: {reply.Error}");
        }
    }

    private static ProgramInfo ToProgramInfo(OpenProgramReply reply) => new()
    {
        Name = reply.ProgramName,
        LanguageId = reply.LanguageId,
        ImageBase = reply.ImageBase,
        FunctionCount = (int)reply.FunctionCount,
    };

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

    /// <summary>Read <paramref name="length"/> raw bytes of program memory starting at <paramref name="address"/> (hex).</summary>
    /// <param name="address">Start address.</param>
    /// <param name="length">Number of bytes to read (the server caps very large reads; fewer may be returned at a memory-block boundary).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, the address is invalid, or the region is unreadable.</exception>
    public async Task<byte[]> ReadBytesAsync(string address, int length, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        var reply = await _client.ReadBytesAsync(
            new ReadBytesRequest { Address = address, Length = length }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"ReadBytes failed: {reply.Error}");
        }
        return reply.Data.ToByteArray();
    }

    /// <summary>
    /// Read the disassembled instructions (the listing) Ghidra already has at
    /// <paramref name="address"/>. Does not run the disassembler — it returns what
    /// analysis produced.
    /// </summary>
    /// <param name="address">Start address (hex).</param>
    /// <param name="maxInstructions">Maximum instructions to return; 0 returns the whole function containing the address (or a default cap when not inside one).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<IReadOnlyList<Instruction>> GetInstructionsAsync(
        string address, int maxInstructions = 0, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetInstructionsAsync(
            new InstructionsRequest { Address = address, MaxInstructions = maxInstructions }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"GetInstructions failed: {reply.Error}");
        }
        return reply.Instructions.Select(i => new Instruction
        {
            Address = i.Address,
            Mnemonic = i.Mnemonic,
            Representation = i.Representation,
            Bytes = i.RawBytes.ToByteArray(),
            Length = i.Length,
        }).ToList();
    }

    /// <summary>Full detail for the function whose entry point is <paramref name="address"/> (hex).</summary>
    /// <param name="address">Entry-point address of the function.</param>
    /// <param name="includeCallers">Populate <see cref="FunctionDetail.Callers"/>.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or no function at the address.</exception>
    public Task<FunctionDetail> GetFunctionAtAsync(string address, bool includeCallers = true, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return GetFunctionAsync(new FunctionRequest { Address = address, IncludeCallers = includeCallers }, ct);
    }

    /// <summary>Full detail for the function named <paramref name="name"/>.</summary>
    /// <param name="name">Function name.</param>
    /// <param name="includeCallers">Populate <see cref="FunctionDetail.Callers"/>.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or no such function.</exception>
    public Task<FunctionDetail> GetFunctionByNameAsync(string name, bool includeCallers = true, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return GetFunctionAsync(new FunctionRequest { Name = name, IncludeCallers = includeCallers }, ct);
    }

    private async Task<FunctionDetail> GetFunctionAsync(FunctionRequest request, CancellationToken ct)
    {
        var reply = await _client.GetFunctionAsync(request, cancellationToken: ct);
        if (!reply.Success || reply.Function is null)
        {
            throw new GhidraException($"GetFunction failed: {reply.Error}");
        }
        var f = reply.Function;
        return new FunctionDetail
        {
            Name = f.Name,
            EntryPoint = f.EntryAddress,
            Signature = f.Signature,
            ReturnType = f.ReturnType,
            CallingConvention = f.CallingConvention,
            NoReturn = f.NoReturn,
            VarArgs = f.Varargs,
            Inline = f.Inline,
            Size = f.Size,
            Parameters = f.Parameters.Select(ToVariable).ToList(),
            Locals = f.LocalVariables.Select(ToVariable).ToList(),
            Callers = f.Callers.ToList(),
        };
    }

    private static GhidraVariable ToVariable(Protocol.Variable v) => new()
    {
        Name = v.Name,
        DataType = v.DataType,
        Storage = v.Storage,
    };

    /// <summary>The defined data item at <paramref name="address"/> (hex). Check <see cref="DataItem.Defined"/> for "nothing there".</summary>
    /// <param name="address">The address to read.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<DataItem> GetDataAtAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetDataAtAsync(new DataAtRequest { Address = address }, cancellationToken: ct);
        return ToDataItem(reply);
    }

    /// <summary>List data types known to the program (structs, enums, typedefs, …), optionally filtered by name.</summary>
    /// <param name="nameContains">Case-insensitive name filter; null/empty returns all.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open.</exception>
    public async Task<IReadOnlyList<GhidraDataType>> ListDataTypesAsync(string? nameContains = null, CancellationToken ct = default)
    {
        var reply = await _client.ListDataTypesAsync(
            new DataTypesRequest { NameContains = nameContains ?? "" }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"ListDataTypes failed: {reply.Error}");
        }
        return reply.DataTypes.Select(d => new GhidraDataType
        {
            Name = d.Name,
            DisplayName = d.DisplayName,
            Path = d.Path,
            Kind = d.Kind,
            Length = d.Length,
        }).ToList();
    }

    /// <summary>
    /// Apply data type <paramref name="dataType"/> at <paramref name="address"/> (by name or path).
    /// The program must be opened writable; the change is in-memory unless saved.
    /// </summary>
    /// <param name="address">Where to apply the type (hex).</param>
    /// <param name="dataType">Name or path of the type, e.g. <c>"float"</c> or <c>"/MyStructs/Header"</c>.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">Unknown type, read-only program, or it cannot be applied there.</exception>
    public async Task<DataItem> ApplyDataTypeAsync(string address, string dataType, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataType);
        var reply = await _client.ApplyDataTypeAsync(
            new ApplyDataTypeRequest { Address = address, DataType = dataType }, cancellationToken: ct);
        return ToDataItem(reply);
    }

    /// <summary>
    /// Escape hatch: run a GhidraScript file against the current program and capture its output.
    /// For the long tail the typed API does not cover — untyped by design.
    /// </summary>
    /// <param name="scriptPath">Path to a GhidraScript file (<c>.java</c>, <c>.py</c>, …).</param>
    /// <param name="args">Arguments passed to the script (available via its <c>getScriptArgs()</c>).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, the script is missing, or it threw.</exception>
    public async Task<ScriptOutput> RunScriptAsync(string scriptPath, IEnumerable<string>? args = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scriptPath);
        var request = new RunScriptRequest { ScriptPath = scriptPath };
        if (args is not null)
        {
            request.Args.AddRange(args);
        }
        var reply = await _client.RunScriptAsync(request, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"RunScript failed: {reply.Error}");
        }
        return new ScriptOutput { Stdout = reply.Stdout, Stderr = reply.Stderr };
    }

    private static DataItem ToDataItem(DataReply reply)
    {
        if (!reply.Success || reply.Data is null)
        {
            throw new GhidraException($"Data request failed: {reply.Error}");
        }
        var d = reply.Data;
        return new DataItem
        {
            Address = d.Address,
            DataType = d.DataType,
            Length = d.Length,
            Value = d.Value,
            IsPointer = d.IsPointer,
            PointerTarget = d.PointerTarget,
            Defined = d.Defined,
        };
    }

    /// <summary>All comment types at <paramref name="address"/> (hex). Empty strings where there's no comment.</summary>
    /// <param name="address">The address to read.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<Comments> GetCommentsAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetCommentsAsync(new CommentsRequest { Address = address }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"GetComments failed: {reply.Error}");
        }
        return new Comments
        {
            Eol = reply.Eol,
            Pre = reply.Pre,
            Post = reply.Post,
            Plate = reply.Plate,
            Repeatable = reply.Repeatable,
        };
    }

    /// <summary>Set (or, with an empty string, clear) a comment of <paramref name="type"/> at <paramref name="address"/>. Needs a writable program.</summary>
    /// <param name="address">The address (hex).</param>
    /// <param name="type">Which comment to set.</param>
    /// <param name="comment">The text; empty clears it.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">Read-only program or invalid address.</exception>
    public async Task SetCommentAsync(string address, CommentType type, string comment, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.SetCommentAsync(
            new SetCommentRequest { Address = address, Type = type.ToString(), Comment = comment ?? "" },
            cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"SetComment failed: {reply.Error}");
        }
    }

    /// <summary>Bookmarks at <paramref name="address"/> (hex).</summary>
    /// <param name="address">The address to read.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, or the address is invalid.</exception>
    public async Task<IReadOnlyList<GhidraBookmark>> GetBookmarksAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetBookmarksAsync(new BookmarksRequest { Address = address }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"GetBookmarks failed: {reply.Error}");
        }
        return reply.Bookmarks.Select(b => new GhidraBookmark
        {
            Address = b.Address,
            Type = b.Type,
            Category = b.Category,
            Comment = b.Comment,
        }).ToList();
    }

    /// <summary>Add a bookmark at <paramref name="address"/>. Needs a writable program.</summary>
    /// <param name="address">The address (hex).</param>
    /// <param name="type">Bookmark type (defaults to <c>"Note"</c> server-side if empty).</param>
    /// <param name="category">Optional category.</param>
    /// <param name="comment">Optional comment.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">Read-only program or invalid address.</exception>
    public async Task SetBookmarkAsync(string address, string type = "Note", string category = "", string comment = "", CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.SetBookmarkAsync(
            new SetBookmarkRequest { Address = address, Type = type ?? "", Category = category ?? "", Comment = comment ?? "" },
            cancellationToken: ct);
        if (!reply.Success)
        {
            throw new GhidraException($"SetBookmark failed: {reply.Error}");
        }
    }

    /// <summary>One instruction in full: structured operands and raw PCode, at <paramref name="address"/> (hex).</summary>
    /// <param name="address">The instruction's address.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="GhidraException">No program is open, no instruction there, or invalid address.</exception>
    public async Task<InstructionDetail> GetInstructionDetailAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var reply = await _client.GetInstructionDetailAsync(
            new InstructionDetailRequest { Address = address }, cancellationToken: ct);
        if (!reply.Success || reply.Instruction is null)
        {
            throw new GhidraException($"GetInstructionDetail failed: {reply.Error}");
        }
        var d = reply.Instruction;
        return new InstructionDetail
        {
            Address = d.Address,
            Mnemonic = d.Mnemonic,
            Representation = d.Representation,
            Bytes = d.RawBytes.ToByteArray(),
            Length = d.Length,
            Operands = d.Operands.Select(o => new Operand
            {
                Index = o.Index,
                Representation = o.Representation,
                Type = o.Type,
                Register = o.Register,
                HasScalar = o.HasScalar,
                Scalar = o.Scalar,
            }).ToList(),
            Pcode = d.Pcode.Select(p => new PcodeOp
            {
                Mnemonic = p.Mnemonic,
                Output = p.Output,
                Inputs = p.Inputs.ToList(),
            }).ToList(),
        };
    }

    private static List<GhidraSymbol> ToSymbols(ListSymbolsReply reply)
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

    private static List<GhidraReference> ToReferences(ReferencesReply reply)
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
