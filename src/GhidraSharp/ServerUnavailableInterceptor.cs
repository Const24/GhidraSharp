using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Const24.GhidraSharp;

/// <summary>
/// Turns the two "no/old server" gRPC failures into a clear <see cref="GhidraException"/>
/// with guidance instead of a raw <see cref="RpcException"/>:
/// <see cref="StatusCode.Unavailable"/> (no server reachable) and
/// <see cref="StatusCode.Unimplemented"/> (the server is older than the client and
/// lacks the called RPC).
/// </summary>
internal sealed class ServerUnavailableInterceptor : Interceptor
{
    private const string Unreachable =
        "Could not reach a GhidraSharpServer. Start one — download ghidrasharp-server from " +
        "https://github.com/Const24/GhidraSharp/releases and run it, or use " +
        "GhidraServer.StartAsync(...) — then retry.";

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var call = continuation(request, context);
        return new AsyncUnaryCall<TResponse>(
            HandleAsync(call.ResponseAsync, context.Method.Name),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private static async Task<TResponse> HandleAsync<TResponse>(Task<TResponse> inner, string method)
    {
        try
        {
            return await inner.ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Unavailable)
        {
            throw new GhidraException(Unreachable, ex);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Unimplemented)
        {
            throw new GhidraException(
                $"The GhidraSharpServer does not implement '{method}'. It is most likely older than " +
                "this client — download a matching server version from " +
                "https://github.com/Const24/GhidraSharp/releases.", ex);
        }
    }
}
