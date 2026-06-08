using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Const24.GhidraSharp.Tests;

/// <summary>
/// Hosts a fake <c>GhidraSharpService</c> on a free loopback port (Kestrel, HTTP/2
/// cleartext — the same transport the real server uses) and hands back a real
/// library <see cref="GhidraClient"/> connected to it. Lets the contract tests
/// exercise the client's wire→DTO mapping with no Ghidra and no JVM.
/// </summary>
internal sealed class FakeServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private FakeServer(WebApplication app, GhidraClient client)
    {
        _app = app;
        Client = client;
    }

    public GhidraClient Client { get; }

    public static async Task<FakeServer> StartAsync<TService>() where TService : class
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k =>
            k.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http2));
        builder.Services.AddGrpc();

        var app = builder.Build();
        app.MapGrpcService<TService>();
        await app.StartAsync();

        var url = app.Urls.First();
        return new FakeServer(app, GhidraClient.Connect(url));
    }

    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        await _app.DisposeAsync();
    }
}
