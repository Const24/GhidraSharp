namespace Const24.GhidraSharp.Tests.Unit;

/// <summary>
/// The launch args must place JVM options (the <c>-Xmx</c> heap cap + any extras) BEFORE the
/// classpath / <c>@argfile</c> — the JVM ignores VM options that follow the main class. These tests
/// pin that ordering and the default heap cap, using a temp argfile so no Ghidra/jars are needed.
/// </summary>
public class JvmArgsTests
{
    [Fact]
    public void Default_options_prepend_the_8_GB_heap_cap_before_the_classpath()
    {
        var argFile = Path.GetTempFileName();
        try
        {
            var args = GhidraServer.BuildLaunchArgs(new GhidraServerOptions { ArgFile = argFile });
            Assert.Equal("-Xmx8192m", args[0]);                          // heap cap first
            Assert.Equal("@" + Path.GetFullPath(argFile), args[^1]);     // classpath last
            Assert.Equal(2, args.Count);
        }
        finally { File.Delete(argFile); }
    }

    [Fact]
    public void A_null_heap_cap_emits_no_Xmx()
    {
        var argFile = Path.GetTempFileName();
        try
        {
            var args = GhidraServer.BuildLaunchArgs(new GhidraServerOptions { ArgFile = argFile, JvmMaxHeapMb = null });
            Assert.DoesNotContain(args, a => a.StartsWith("-Xmx", StringComparison.Ordinal));
            Assert.Equal("@" + Path.GetFullPath(argFile), args[^1]);
        }
        finally { File.Delete(argFile); }
    }

    [Fact]
    public void Custom_heap_then_extra_jvm_args_all_precede_the_classpath_in_order()
    {
        var argFile = Path.GetTempFileName();
        try
        {
            var args = GhidraServer.BuildLaunchArgs(new GhidraServerOptions
            {
                ArgFile = argFile,
                JvmMaxHeapMb = 2048,
                JvmArgs = ["-XX:+UseG1GC"],
            });
            Assert.Equal("-Xmx2048m", args[0]);                          // -Xmx first
            Assert.Equal("-XX:+UseG1GC", args[1]);                       // extras after -Xmx
            Assert.Equal("@" + Path.GetFullPath(argFile), args[^1]);     // classpath last
        }
        finally { File.Delete(argFile); }
    }
}
