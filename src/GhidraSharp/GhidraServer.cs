using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Const24.GhidraSharp;

/// <summary>Options for launching a <see cref="GhidraServer"/>.</summary>
public sealed class GhidraServerOptions
{
    /// <summary>
    /// Path to the Java <c>@argfile</c> produced by the server's
    /// <c>writeServerArgs</c> Gradle task (classpath + main class).
    /// </summary>
    public required string ArgFile { get; init; }

    /// <summary>Java executable. Defaults to <c>$JAVA_HOME/bin/java</c>, else <c>java</c> on PATH.</summary>
    public string? JavaExe { get; init; }

    /// <summary>Ghidra installation directory, passed as <c>GHIDRA_INSTALL_DIR</c>. Defaults to the server's own fallback.</summary>
    public string? GhidraInstallDir { get; init; }

    /// <summary>TCP port to serve on. <c>null</c> picks a free port automatically.</summary>
    public int? Port { get; init; }

    /// <summary>How long to wait for the server to start listening before failing.</summary>
    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(120);
}

/// <summary>
/// Owns a spawned Java <c>GhidraSharpServer</c> process and a <see cref="GhidraClient"/>
/// connected to it. Dispose to shut the server down.
/// </summary>
/// <remarks>
/// This is the dev/embedding convenience: no manual <c>gradlew run</c>, no port
/// juggling. Run the <c>writeServerArgs</c> Gradle task once to produce the
/// argfile, then <see cref="StartAsync"/> handles the rest.
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

    /// <summary>Launch the server and return once it is accepting connections.</summary>
    public static async Task<GhidraServer> StartAsync(GhidraServerOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var argFile = Path.GetFullPath(options.ArgFile);
        if (!File.Exists(argFile))
        {
            throw new FileNotFoundException(
                $"Java argfile not found: {argFile}. Run the server's 'writeServerArgs' Gradle task first.", argFile);
        }

        int port = options.Port ?? FindFreePort();

        var psi = new ProcessStartInfo
        {
            FileName = ResolveJava(options.JavaExe),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("@" + argFile);
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

    private static int FindFreePort()
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

    private static string ResolveJava(string? javaExe)
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
        await Client.DisposeAsync();
        TryKill(_process);
        _process.Dispose();
    }
}
