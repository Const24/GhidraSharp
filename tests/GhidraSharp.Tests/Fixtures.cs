namespace Const24.GhidraSharp.Tests;

/// <summary>Starts one <see cref="HappyFake"/> server for a whole test class and shares its client.</summary>
public sealed class HappyServerFixture : IAsyncLifetime
{
    private FakeServer? _server;

    public GhidraClient Client => _server!.Client;

    public async Task InitializeAsync() => _server = await FakeServer.StartAsync<HappyFake>();

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }
}

/// <summary>Starts one <see cref="FailingFake"/> server (every RPC fails) for a test class.</summary>
public sealed class FailingServerFixture : IAsyncLifetime
{
    private FakeServer? _server;

    public GhidraClient Client => _server!.Client;

    public async Task InitializeAsync() => _server = await FakeServer.StartAsync<FailingFake>();

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }
}
