namespace Const24.GhidraSharp.Tests;

/// <summary>Starts one fake server for a whole test class and shares its client.
/// xUnit class fixtures must be concrete, so each fake gets a thin subclass.</summary>
public abstract class FakeServerFixture : IAsyncLifetime
{
    private FakeServer? _server;

    public GhidraClient Client => _server!.Client;

    public string Url => _server!.Url;

    internal abstract Task<FakeServer> StartServerAsync();

    public async Task InitializeAsync() => _server = await StartServerAsync();

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }
}

/// <summary>Shares a <see cref="HappyFake"/> server (canned success data for every RPC).</summary>
public sealed class HappyServerFixture : FakeServerFixture
{
    internal override Task<FakeServer> StartServerAsync() => FakeServer.StartAsync<HappyFake>();
}

/// <summary>Shares a <see cref="FailingFake"/> server (every RPC fails).</summary>
public sealed class FailingServerFixture : FakeServerFixture
{
    internal override Task<FakeServer> StartServerAsync() => FakeServer.StartAsync<FailingFake>();
}
