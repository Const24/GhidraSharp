namespace Const24.GhidraSharp.Tests.Unit;

public class GhidraServerTests
{
    [Fact]
    public void FindFreePort_returns_a_usable_port()
    {
        var port = GhidraServer.FindFreePort();
        Assert.InRange(port, 1, 65535);
    }

    [Fact]
    public void ResolveJava_returns_an_explicit_executable_unchanged() => Assert.Equal("/opt/jdk/bin/java", GhidraServer.ResolveJava("/opt/jdk/bin/java"));

    [Fact]
    public async Task StartAsync_throws_a_clear_error_when_the_argfile_is_missing()
    {
        var options = new GhidraServerOptions { ArgFile = "definitely-not-here.args" };
        await Assert.ThrowsAsync<FileNotFoundException>(() => GhidraServer.StartAsync(options));
    }
}
