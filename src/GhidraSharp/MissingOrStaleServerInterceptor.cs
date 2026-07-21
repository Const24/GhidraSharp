using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Const24.GhidraSharp;

/// <summary>
/// Turns the two "no/old server" gRPC failures into a clear <see cref="GhidraException"/>
/// with guidance instead of a raw <see cref="RpcException"/>:
/// <see cref="StatusCode.Unavailable"/> (no server reachable) and
/// <see cref="StatusCode.Unimplemented"/> (the server is older than the client and lacks
/// the called RPC). Covers unary and server-streaming calls — the only shapes the client uses.
/// </summary>
internal sealed class MissingOrStaleServerInterceptor : Interceptor
{
    private const string Unreachable =
        "Could not reach a GhidraSharpServer. Start one — download ghidrasharp-server from " +
        "https://github.com/Const24/GhidraSharp/releases and run it, or use " +
        "GhidraServer.StartAsync(...) — then retry.";

    private static GhidraException Translate(RpcException ex, string method) =>
        ex.StatusCode == StatusCode.Unavailable
            ? new GhidraException(Unreachable, ex)
            : new GhidraException(
                $"The GhidraSharpServer does not implement '{method}'. It is most likely older than " +
                "this client — download a matching server version from " +
                "https://github.com/Const24/GhidraSharp/releases.", ex);

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

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        var call = continuation(request, context);
        return new AsyncServerStreamingCall<TResponse>(
            new TranslatingReader<TResponse>(call.ResponseStream, context.Method.Name),
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
        catch (RpcException ex) when (ex.StatusCode is StatusCode.Unavailable or StatusCode.Unimplemented)
        {
            throw Translate(ex, method);
        }
    }

    private sealed class TranslatingReader<TResponse>(IAsyncStreamReader<TResponse> inner, string method)
        : IAsyncStreamReader<TResponse>
    {
        public TResponse Current => inner.Current;

        public async Task<bool> MoveNext(CancellationToken cancellationToken)
        {
            try
            {
                return await inner.MoveNext(cancellationToken).ConfigureAwait(false);
            }
            catch (RpcException ex) when (ex.StatusCode is StatusCode.Unavailable or StatusCode.Unimplemented)
            {
                throw Translate(ex, method);
            }
        }
    }
}
