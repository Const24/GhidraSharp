namespace Const24.GhidraSharp.Tests;

/// <summary>Sets a process-global environment variable for a scope and restores the
/// previous value on dispose. Callers that set the same variable must share one xUnit
/// collection — the scope guards against leaks, not against parallel tests.</summary>
internal sealed class EnvVarScope : IDisposable
{
    private readonly string _name;
    private readonly string? _previous;

    public EnvVarScope(string name, string? value)
    {
        _name = name;
        _previous = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
    }

    public void Dispose() => Environment.SetEnvironmentVariable(_name, _previous);
}
