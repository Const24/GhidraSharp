using System.Diagnostics;

namespace Const24.GhidraSharp.Tests.Integration;

/// <summary>
/// Drives a real <see cref="GhidraServerPool"/> of spawned servers. Uses the <c>stub</c> engine
/// (GHIDRASHARP_ENGINE=stub) so no Ghidra is needed — only a JDK and the launch argfile
/// (run <c>server/gradlew writeServerArgs</c>). Skipped otherwise.
/// </summary>
// Serialize the server-spawning integration classes: ServerPoolTests sets the process-global
// GHIDRASHARP_ENGINE, which must not race with EngineIntegrationTests' real-Ghidra servers.
[CollectionDefinition("Ghidra servers", DisableParallelization = true)]
public sealed class GhidraServerCollection { }

[Trait("Category", "Integration")]
[Collection("Ghidra servers")]
public sealed class ServerPoolTests
{
    private sealed class Recorder : IProgress<PoolProgress>
    {
        private readonly object _lock = new();
        public PoolProgress Last { get; private set; }
        public int Reports { get; private set; }
        public void Report(PoolProgress value)
        {
            lock (_lock) { Last = value; Reports++; }
        }
    }

    [SkippableFact]
    public async Task Pool_runs_every_item_across_servers_and_reports_progress()
    {
        var (ok, reason, argFile) = Gate();
        Skip.IfNot(ok, reason);
        using var _ = StubEngine();

        await using var pool = await GhidraServerPool.StartAsync(2, new GhidraServerOptions { ArgFile = argFile });
        Assert.Equal(2, pool.Size);

        var progress = new Recorder();
        var results = await pool.ForEachAsync(
            Enumerable.Range(0, 6),
            async (client, _, ct) => await client.PingAsync(ct),
            progress);

        Assert.Equal(6, results.Count);
        Assert.All(results, r => Assert.True(r.Ok));
        Assert.Equal(new PoolProgress(6, 6, 0), progress.Last);
    }

    [SkippableFact]
    public async Task Pool_captures_per_item_errors_and_keeps_going()
    {
        var (ok, reason, argFile) = Gate();
        Skip.IfNot(ok, reason);
        using var _ = StubEngine();

        await using var pool = await GhidraServerPool.StartAsync(2, new GhidraServerOptions { ArgFile = argFile });

        var results = await pool.ForEachAsync(Enumerable.Range(0, 6), async (client, i, ct) =>
        {
            await client.PingAsync(ct);
            if (i % 2 == 0) throw new InvalidOperationException($"boom {i}");
        });

        Assert.Equal(3, results.Count(r => r.Ok));   // odd items
        Assert.Equal(3, results.Count(r => !r.Ok));  // even items threw
        Assert.All(results.Where(r => !r.Ok), r => Assert.IsType<InvalidOperationException>(r.Error));
    }

    [SkippableFact]
    public async Task A_crashed_server_is_restarted_and_the_batch_finishes()
    {
        var (ok, reason, argFile) = Gate();
        Skip.IfNot(ok, reason);
        using var _ = StubEngine();

        await using var pool = await GhidraServerPool.StartAsync(1, new GhidraServerOptions { ArgFile = argFile });
        var killed = false;

        var results = await pool.ForEachAsync(Enumerable.Range(0, 4), async (client, i, ct) =>
        {
            if (i == 1 && !killed)
            {
                killed = true;
                pool.Servers[0].Kill(); // crash the only server mid-batch
            }
            await client.PingAsync(ct); // fails on the dead server -> pool restarts + retries once
        });

        Assert.True(killed);
        Assert.Equal(4, results.Count);
        Assert.All(results, r => Assert.True(r.Ok)); // item 1 succeeds after restart
    }

    // --- gate + stub-engine scope ------------------------------------------------

    private static (bool ok, string reason, string argFile) Gate()
    {
        var root = FindRepoRoot();
        var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        var argFile = root is null ? null : Path.Combine(root, "server", "build", "ghidrasharp-java.args");
        if (string.IsNullOrEmpty(javaHome) || argFile is null || !File.Exists(argFile))
        {
            return (false, "set JAVA_HOME and run `server/gradlew writeServerArgs`", "");
        }
        return (true, "", argFile);
    }

    private static IDisposable StubEngine()
    {
        var prev = Environment.GetEnvironmentVariable("GHIDRASHARP_ENGINE");
        Environment.SetEnvironmentVariable("GHIDRASHARP_ENGINE", "stub");
        return new Restore(() => Environment.SetEnvironmentVariable("GHIDRASHARP_ENGINE", prev));
    }

    private static string? FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "GhidraSharp.slnx")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName;
    }

    private sealed class Restore(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }
}
