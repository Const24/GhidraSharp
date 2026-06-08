using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Const24.GhidraSharp;

/// <summary>
/// Translates a "server unreachable" gRPC failure (<see cref="StatusCode.Unavailable"/>)
/// into a clear <see cref="GhidraException"/> that tells the caller how to get a
/// server running, instead of surfacing a raw <see cref="RpcException"/>.
/// </summary>
internal sealed class ServerUnavailableInterceptor : Interceptor
{
    private const string Hint =
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
            HandleAsync(call.ResponseAsync),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private static async Task<TResponse> HandleAsync<TResponse>(Task<TResponse> inner)
    {
        try
        {
            return await inner.ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Unavailable)
        {
            throw new GhidraException(Hint, ex);
        }
    }
}
