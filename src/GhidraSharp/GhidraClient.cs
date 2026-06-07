using Grpc.Net.Client;
using Const24.GhidraSharp.Protocol;
using ProtoSvc = Const24.GhidraSharp.Protocol.GhidraSharpService;

namespace Const24.GhidraSharp;

/// <summary>
/// Typed C# entry point to a running <c>GhidraSharpServer</c> (Ghidra-as-library)
/// over gRPC. Wraps the generated client so callers work with intent-named async
/// methods and never touch the raw channel or the generated stub.
/// </summary>
/// <remarks>
/// One <see cref="GhidraClient"/> owns one channel; create it once and reuse it.
/// The server holds a single "current program" — call
/// <see cref="OpenProgramAsync"/> before decompiling.
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
    public static GhidraClient Connect(string address)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return new GhidraClient(GrpcChannel.ForAddress(address));
    }

    /// <summary>Connect using an already-configured channel (custom credentials, handler, etc.).</summary>
    public static GhidraClient FromChannel(GrpcChannel channel)
        => new(channel ?? throw new ArgumentNullException(nameof(channel)));

    /// <summary>Liveness + handshake. Returns the Ghidra version the server is running.</summary>
    public async Task<PingReply> PingAsync(string message = "", CancellationToken ct = default)
        => await _client.PingAsync(new PingRequest { Message = message }, cancellationToken: ct);

    /// <summary>
    /// Open (importing + analyzing if needed) a program and make it the server's
    /// current program for subsequent calls.
    /// </summary>
    public async Task<OpenProgramReply> OpenProgramAsync(
        string programPath,
        string projectPath = "",
        string languageId = "",
        bool analyze = true,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(programPath);
        var request = new OpenProgramRequest
        {
            ProgramPath = programPath,
            ProjectPath = projectPath,
            LanguageId = languageId,
            Analyze = analyze,
        };
        return await _client.OpenProgramAsync(request, cancellationToken: ct);
    }

    /// <summary>Decompile a function identified by entry <paramref name="address"/> (hex like <c>0x21e0</c>).</summary>
    public Task<DecompileReply> DecompileAtAsync(string address, int timeoutSeconds = 0, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return DecompileAsync(new DecompileRequest { Address = address, TimeoutSeconds = timeoutSeconds }, ct);
    }

    /// <summary>Decompile a function identified by <paramref name="name"/>.</summary>
    public Task<DecompileReply> DecompileByNameAsync(string name, int timeoutSeconds = 0, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return DecompileAsync(new DecompileRequest { Name = name, TimeoutSeconds = timeoutSeconds }, ct);
    }

    private async Task<DecompileReply> DecompileAsync(DecompileRequest request, CancellationToken ct)
        => await _client.DecompileFunctionAsync(request, cancellationToken: ct);

    /// <summary>
    /// List the functions in the current program. The result is a plain list,
    /// ready to query with LINQ (e.g. <c>funcs.Where(f =&gt; f.Calls.Contains("..."))</c>).
    /// </summary>
    /// <param name="includeCalls">
    /// Populate each function's <c>Calls</c> (its callees). Costs an extra pass
    /// over the call graph server-side.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<IReadOnlyList<FunctionInfo>> ListFunctionsAsync(bool includeCalls = false, CancellationToken ct = default)
    {
        var reply = await _client.ListFunctionsAsync(
            new ListFunctionsRequest { IncludeCalls = includeCalls }, cancellationToken: ct);
        if (!reply.Success)
        {
            throw new InvalidOperationException($"ListFunctions failed: {reply.Error}");
        }
        return reply.Functions;
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
