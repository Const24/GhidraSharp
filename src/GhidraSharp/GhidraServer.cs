using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Const24.GhidraSharp;

/// <summary>Options for launching a <see cref="GhidraServer"/>.</summary>
public sealed class GhidraServerOptions
{
    /// <summary>
    /// Path to an unzipped server distribution (the folder holding <c>lib/</c>). Leave
    /// <c>null</c> to auto-detect: a <c>ghidrasharp-server</c> folder next to the app
    /// (shipped by the <c>Const24.GhidraSharp.Server</c> package), else the
    /// <c>GHIDRASHARP_SERVER_DIR</c> environment variable. Set explicitly only to override,
    /// or use <see cref="ArgFile"/> for a source build.
    /// </summary>
    public string? ServerDirectory { get; init; }

    /// <summary>
    /// Path to the Java <c>@argfile</c> produced by the server's <c>writeServerArgs</c>
    /// Gradle task (classpath + main class) — for running from a source build. Set this
    /// <b>or</b> <see cref="ServerDirectory"/>.
    /// </summary>
    public string? ArgFile { get; init; }

    /// <summary>Java executable. Defaults to <c>$JAVA_HOME/bin/java</c>, else <c>java</c> on PATH.</summary>
    public string? JavaExe { get; init; }

    /// <summary>Ghidra installation directory, passed as <c>GHIDRA_INSTALL_DIR</c>. Defaults to the server's own fallback.</summary>
    public string? GhidraInstallDir { get; init; }

    /// <summary>TCP port to serve on. <c>null</c> picks a free port automatically.</summary>
    public int? Port { get; init; }

    /// <summary>How long to wait for the server to start listening before failing.</summary>
    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Max JVM heap in MB (<c>-Xmx</c>) for the server process. Defaults to <c>8192</c>. Left unset, HotSpot's default
    /// max heap is a quarter of physical RAM — far too large when a <see cref="GhidraServerPool"/> runs many servers
    /// on one host (N × ¼-RAM overcommits and OOMs), so a cap is applied by default to keep the pool's memory ceiling
    /// predictable. This is a CEILING, not a reservation (no <c>-Xms</c>): small programs stay well under it while a
    /// large binary's analysis can still use the headroom it needs, so the default is set generously. On a
    /// RAM-constrained host running a big pool, lower it (roughly host RAM ÷ pool size, leaving room for each
    /// server's native decompiler); set <c>null</c> to inherit the JVM default.
    /// </summary>
    public int? JvmMaxHeapMb { get; init; } = 8192;

    /// <summary>Extra JVM options placed before the classpath (e.g. GC flags). Optional; applied after <c>-Xmx</c>.</summary>
    public IReadOnlyList<string>? JvmArgs { get; init; }
}

/// <summary>
/// Owns a spawned Java <c>GhidraSharpServer</c> process and a <see cref="GhidraClient"/>
/// connected to it. Dispose to shut the server down.
/// </summary>
/// <remarks>
/// Point <see cref="GhidraServerOptions.ServerDirectory"/> at an unzipped
/// <c>ghidrasharp-server</c> (download it from the GitHub Releases) and
/// <see cref="StartAsync"/> launches it for you — no manual run, no port juggling.
/// When building from source, set <see cref="GhidraServerOptions.ArgFile"/> from the
/// <c>writeServerArgs</c> task instead.
/// </remarks>
public sealed class GhidraServer : IAsyncDisposable, IDisposable
{
    private readonly Process _process;

    private GhidraServer(Process process, GhidraClient client, int port)
    {
        _process = process;
        Client = client;
        Port = port;
    }

    /// <summary>The connected client for this server.</summary>
    public GhidraClient Client { get; }

    /// <summary>The port the server is listening on.</summary>
    public int Port { get; }

    /// <summary>Whether the underlying server process has exited (the pool uses this to detect a crash).</summary>
    public bool HasExited
    {
        get
        {
            try { return _process.HasExited; }
            catch { return true; }
        }
    }

    /// <summary>Launch the server and return once it is accepting connections.</summary>
    public static async Task<GhidraServer> StartAsync(GhidraServerOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var launchArgs = BuildLaunchArgs(options);

        var port = options.Port ?? FindFreePort();

        var psi = new ProcessStartInfo
        {
            FileName = ResolveJava(options.JavaExe),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in launchArgs)
        {
            psi.ArgumentList.Add(arg);
        }
        psi.Environment["GHIDRASHARP_PORT"] = port.ToString();
        if (!string.IsNullOrWhiteSpace(options.GhidraInstallDir))
        {
            psi.Environment["GHIDRA_INSTALL_DIR"] = options.GhidraInstallDir;
        }

        var log = new StringBuilder();
        var process = new Process { StartInfo = psi };
        process.OutputDataReceived += (_, e) => Append(log, e.Data);
        process.ErrorDataReceived += (_, e) => Append(log, e.Data);

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        try
        {
            await WaitUntilListening(process, port, options.StartupTimeout, log, ct);
        }
        catch
        {
            TryKill(process);
            throw;
        }

        var client = GhidraClient.Connect($"http://127.0.0.1:{port}");
        return new GhidraServer(process, client, port);
    }

    private static async Task WaitUntilListening(
        Process process, int port, TimeSpan timeout, StringBuilder log, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                throw new InvalidOperationException(
                    $"GhidraSharpServer exited with code {process.ExitCode} before listening.\n{log}");
            }
            if (await CanConnect(port, ct))
            {
                return;
            }
            await Task.Delay(200, ct);
        }
        throw new TimeoutException(
            $"GhidraSharpServer did not start listening on port {port} within {timeout.TotalSeconds:F0}s.\n{log}");
    }

    private static async Task<bool> CanConnect(int port, CancellationToken ct)
    {
        try
        {
            using var probe = new TcpClient();
            await probe.ConnectAsync(IPAddress.Loopback, port, ct);
            return true;
        }
        catch
        {
            return false;
        }
    }

    internal static int FindFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    internal static string ResolveJava(string? javaExe)
    {
        if (!string.IsNullOrWhiteSpace(javaExe))
        {
            return javaExe;
        }
        var home = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(home))
        {
            var candidate = Path.Combine(home, "bin", OperatingSystem.IsWindows() ? "java.exe" : "java");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        return OperatingSystem.IsWindows() ? "java.exe" : "java";
    }

    private const string MainClass = "io.github.const24.ghidrasharp.server.GhidraSharpServer";

    internal static List<string> BuildLaunchArgs(GhidraServerOptions options)
    {
        // JVM options MUST precede -cp / @argfile. -Xmx caps each server's heap so a pool of N servers has a
        // predictable memory ceiling instead of the HotSpot default (¼ of physical RAM) × N.
        var args = JvmArgs(options);
        var serverDir = ResolveServerDirectory(options);
        if (serverDir is not null)
        {
            args.AddRange(BuildClasspathArgs(serverDir, options));
            return args;
        }
        if (!string.IsNullOrWhiteSpace(options.ArgFile))
        {
            var argFile = Path.GetFullPath(options.ArgFile);
            if (!File.Exists(argFile))
            {
                throw new FileNotFoundException(
                    $"Java argfile not found: {argFile}. Run the server's 'writeServerArgs' Gradle task first.", argFile);
            }
            args.Add("@" + argFile);
            return args;
        }
        throw new InvalidOperationException(
            "No GhidraSharpServer found. Install the Const24.GhidraSharp.Server package (it ships one next " +
            "to your app), or download ghidrasharp-server from https://github.com/Const24/GhidraSharp/releases " +
            "and set GhidraServerOptions.ServerDirectory, or set ArgFile when building from source.");
    }

    // JVM options that precede the classpath: the -Xmx cap (default 8 GB) plus any caller-supplied extras.
    private static List<string> JvmArgs(GhidraServerOptions options)
    {
        var args = new List<string>();
        if (options.JvmMaxHeapMb is int mb && mb > 0)
        {
            args.Add($"-Xmx{mb}m");
        }
        if (options.JvmArgs is { Count: > 0 })
        {
            args.AddRange(options.JvmArgs);
        }
        return args;
    }

    // Resolve the server distribution: explicit ServerDirectory, else GHIDRASHARP_SERVER_DIR,
    // else a 'ghidrasharp-server' folder next to the app (dropped by Const24.GhidraSharp.Server).
    internal static string? ResolveServerDirectory(GhidraServerOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.ServerDirectory))
        {
            return Path.GetFullPath(options.ServerDirectory);
        }
        var env = Environment.GetEnvironmentVariable("GHIDRASHARP_SERVER_DIR");
        if (!string.IsNullOrWhiteSpace(env) && IsServerDirectory(env))
        {
            return Path.GetFullPath(env);
        }
        var beside = Path.Combine(AppContext.BaseDirectory, "ghidrasharp-server");
        return IsServerDirectory(beside) ? beside : null;
    }

    private static bool IsServerDirectory(string dir) => Directory.Exists(Path.Combine(dir, "lib"));

    private static List<string> BuildClasspathArgs(string serverDir, GhidraServerOptions options)
    {
        var dir = Path.GetFullPath(serverDir);
        var libDir = Path.Combine(dir, "lib");
        if (!Directory.Exists(libDir))
        {
            throw new DirectoryNotFoundException(
                $"ServerDirectory '{dir}' has no lib/ folder. Point it at an unzipped " +
                "ghidrasharp-server-<version> from https://github.com/Const24/GhidraSharp/releases.");
        }

        var ghidra = options.GhidraInstallDir ?? Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
        if (string.IsNullOrWhiteSpace(ghidra) || !Directory.Exists(ghidra))
        {
            throw new DirectoryNotFoundException(
                "Ghidra install not found. Set GhidraServerOptions.GhidraInstallDir (or the " +
                "GHIDRA_INSTALL_DIR environment variable) to your Ghidra 12.x install.");
        }

        var jars = new List<string>(Directory.GetFiles(libDir, "*.jar"));
        jars.AddRange(FindGhidraJars(ghidra));

        return ["-cp", string.Join(Path.PathSeparator, jars), MainClass];
    }

    // Mirrors the server build's Ghidra fileTree: Ghidra/**/lib/*.jar, minus the Debug
    // tree, guava (gRPC's is used instead), and -src jars.
    private static IEnumerable<string> FindGhidraJars(string ghidraInstall)
    {
        var root = Path.Combine(ghidraInstall, "Ghidra");
        if (!Directory.Exists(root))
        {
            return [];
        }
        return Directory.EnumerateFiles(root, "*.jar", SearchOption.AllDirectories)
            .Where(p =>
            {
                var u = p.Replace('\\', '/');
                var name = Path.GetFileName(p);
                return u.Contains("/lib/")
                    && !u.Contains("/Debug/")
                    && !name.StartsWith("guava", StringComparison.OrdinalIgnoreCase)
                    && !name.EndsWith("-src.jar", StringComparison.OrdinalIgnoreCase);
            });
    }

    private static void Append(StringBuilder log, string? line)
    {
        if (line is null)
        {
            return;
        }
        lock (log)
        {
            log.AppendLine(line);
        }
    }

    /// <summary>Force-kill the server process and wait for it to exit (test hook to simulate a crash).</summary>
    internal void Kill()
    {
        TryKill(_process);
        try { _process.WaitForExit(5000); } catch { /* best effort */ }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // best effort
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Client.Dispose();
        TryKill(_process);
        _process.Dispose();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await TryReleaseAsync();
        await Client.DisposeAsync();
        TryKill(_process);
        _process.Dispose();
    }

    // Best-effort: ask the server to close its current project so it releases the on-disk
    // lock before we kill the process. Bounded so a hung or crashed server can't block disposal.
    private async Task TryReleaseAsync()
    {
        if (_process.HasExited)
        {
            return;
        }
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Client.CloseProgramAsync(cts.Token);
        }
        catch
        {
            // server may be mid-operation or unreachable; the kill below still cleans up
        }
    }
}
