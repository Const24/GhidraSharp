using System.Threading.Channels;

namespace Const24.GhidraSharp;

/// <summary>Per-item outcome of a <see cref="GhidraServerPool.ForEachAsync{T}"/> batch.</summary>
public readonly record struct PoolResult<T>(T Item, bool IsSuccess, Exception? Error);

/// <summary>Progress snapshot for an in-flight pool batch (for <see cref="IProgress{T}"/>).</summary>
public readonly record struct PoolProgress(int Done, int Total, int Failed);

/// <summary>
/// Owns N independent <see cref="GhidraServer"/> instances (N JVMs) and distributes batch
/// work across them — process-level parallelism for whole-corpus operations.
/// </summary>
/// <remarks>
/// A single server is single-program and serialized by design (Ghidra analysis isn't safe for
/// concurrent multi-program work in one JVM). Parallelism therefore means N separate servers.
/// Each item is handled by exactly one server for its whole duration: a <see cref="Channel{T}"/>
/// feeds N workers, each owning its own server and pulling items — so two items never land on
/// the same server at once. A worker whose server process dies restarts it and retries the item
/// once, so the pool stays at N and the batch finishes.
/// </remarks>
public sealed class GhidraServerPool : IAsyncDisposable
{
    private readonly GhidraServer[] _servers;
    private readonly GhidraServerOptions _serverOptions;
    // Serializes slot replacement against disposal: a worker restarting a slot must never
    // publish a fresh server after DisposeAsync has swept the array (an orphaned JVM).
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private bool _disposed;

    private GhidraServerPool(GhidraServer[] servers, GhidraServerOptions serverOptions)
    {
        _servers = servers;
        _serverOptions = serverOptions;
    }

    /// <summary>Number of servers in the pool.</summary>
    public int Size => _servers.Length;

    /// <summary>The pooled servers (slots; a slot's server is replaced if it is restarted).</summary>
    public IReadOnlyList<GhidraServer> Servers => _servers;

    /// <summary>Spawn <paramref name="size"/> servers in parallel (each its own JVM + free port);
    /// returns once all are listening. If any fails to start, the ones that came up are stopped.</summary>
    public static async Task<GhidraServerPool> StartAsync(
        int size, GhidraServerOptions serverOptions, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);
        ArgumentNullException.ThrowIfNull(serverOptions);

        var tasks = new Task<GhidraServer>[size];
        for (var i = 0; i < size; i++)
        {
            tasks[i] = GhidraServer.StartAsync(serverOptions, ct);
        }
        try
        {
            var servers = await Task.WhenAll(tasks).ConfigureAwait(false);
            return new GhidraServerPool(servers, serverOptions);
        }
        catch
        {
            foreach (var t in tasks)
            {
                if (t.IsCompletedSuccessfully)
                {
                    try { await t.Result.DisposeAsync().ConfigureAwait(false); } catch { /* best effort */ }
                }
            }
            throw;
        }
    }

    /// <summary>Run <paramref name="body"/> for every item, one item per server at a time. Per-item
    /// exceptions are captured into the result (never crash the pool); progress is reported as items
    /// complete. Results are returned in the same order as <paramref name="items"/>.</summary>
    public async Task<IReadOnlyList<PoolResult<T>>> ForEachAsync<T>(
        IEnumerable<T> items,
        Func<GhidraClient, T, CancellationToken, Task> body,
        IProgress<PoolProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(body);

        var work = items as IReadOnlyList<T> ?? [.. items];
        var total = work.Count;
        var results = new PoolResult<T>[total];
        if (total == 0)
        {
            return results;
        }

        var channel = Channel.CreateUnbounded<int>(new UnboundedChannelOptions { SingleWriter = true });
        for (var i = 0; i < total; i++)
        {
            channel.Writer.TryWrite(i);
        }
        channel.Writer.Complete();

        var done = 0;
        var failed = 0;

        async Task Worker(int slot)
        {
            while (await channel.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                while (channel.Reader.TryRead(out var idx))
                {
                    var result = await RunItemAsync(slot, work[idx], body, ct).ConfigureAwait(false);
                    results[idx] = result;

                    var d = Interlocked.Increment(ref done);
                    var f = result.IsSuccess ? Volatile.Read(ref failed) : Interlocked.Increment(ref failed);
                    progress?.Report(new PoolProgress(d, total, f));
                }
            }
        }

        var workers = new Task[_servers.Length];
        for (var s = 0; s < _servers.Length; s++)
        {
            workers[s] = Worker(s);
        }
        await Task.WhenAll(workers).ConfigureAwait(false);
        return results;
    }

    private async Task<PoolResult<T>> RunItemAsync<T>(
        int slot, T item, Func<GhidraClient, T, CancellationToken, Task> body, CancellationToken ct)
    {
        try
        {
            await body(_servers[slot].Client, item, ct).ConfigureAwait(false);
            return new PoolResult<T>(item, true, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Server still alive => an item-level failure: record and move on.
            if (!_servers[slot].HasExited)
            {
                return new PoolResult<T>(item, false, ex);
            }

            // Server process died => restart this slot and retry the item once.
            try
            {
                await RestartSlotAsync(slot, ct).ConfigureAwait(false);
                await body(_servers[slot].Client, item, ct).ConfigureAwait(false);
                return new PoolResult<T>(item, true, null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception retryEx)
            {
                return new PoolResult<T>(item, false, retryEx);
            }
        }
    }

    private async Task RestartSlotAsync(int slot, CancellationToken ct)
    {
        var dead = _servers[slot];
        var fresh = await GhidraServer.StartAsync(_serverOptions, ct).ConfigureAwait(false);
        await _lifecycle.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                try { await fresh.DisposeAsync().ConfigureAwait(false); } catch { /* best effort */ }
                throw new ObjectDisposedException(nameof(GhidraServerPool));
            }
            _servers[slot] = fresh;
        }
        finally
        {
            _lifecycle.Release();
        }
        try { await dead.DisposeAsync().ConfigureAwait(false); } catch { /* best effort */ }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _lifecycle.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
        }
        finally
        {
            _lifecycle.Release();
        }
        foreach (var server in _servers)
        {
            try { await server.DisposeAsync().ConfigureAwait(false); } catch { /* best effort */ }
        }
    }
}
