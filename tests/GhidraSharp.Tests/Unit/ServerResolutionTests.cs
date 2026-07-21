namespace Const24.GhidraSharp.Tests.Unit;

// GHIDRASHARP_SERVER_DIR is process-global; xUnit runs test classes in parallel. Every
// test that sets or reads it must sit in this collection so they serialize.
[CollectionDefinition("GHIDRASHARP_SERVER_DIR")]
public sealed class ServerDirEnvVarSerialization { }

[Collection("GHIDRASHARP_SERVER_DIR")]
public sealed class ServerResolutionTests
{
    [Fact]
    public void Explicit_ServerDirectory_is_returned_as_a_full_path()
    {
        var dir = GhidraServer.ResolveServerDirectory(new GhidraServerOptions { ServerDirectory = "some/dir" });
        Assert.Equal(Path.GetFullPath("some/dir"), dir);
    }

    [Fact]
    public void GHIDRASHARP_SERVER_DIR_is_used_when_it_has_a_lib_folder()
    {
        var tmp = Directory.CreateTempSubdirectory("ghs_srv_").FullName;
        Directory.CreateDirectory(Path.Combine(tmp, "lib"));
        try
        {
            using var env = new EnvVarScope("GHIDRASHARP_SERVER_DIR", tmp);
            Assert.Equal(Path.GetFullPath(tmp), GhidraServer.ResolveServerDirectory(new GhidraServerOptions()));
        }
        finally
        {
            Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void A_GHIDRASHARP_SERVER_DIR_without_a_lib_folder_is_ignored()
    {
        var tmp = Directory.CreateTempSubdirectory("ghs_srv_").FullName; // no lib/
        try
        {
            using var env = new EnvVarScope("GHIDRASHARP_SERVER_DIR", tmp);
            // no lib/ in the env dir, and the test host has no server folder beside it
            Assert.Null(GhidraServer.ResolveServerDirectory(new GhidraServerOptions()));
        }
        finally
        {
            Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void An_explicit_ArgFile_beats_a_set_GHIDRASHARP_SERVER_DIR()
    {
        // The env dir is valid (has lib/), so it would win as an ambient fallback —
        // but an explicit ArgFile is a configured launch and must take precedence.
        var envDir = Directory.CreateTempSubdirectory("ghs_srv_").FullName;
        Directory.CreateDirectory(Path.Combine(envDir, "lib"));
        var argFile = Path.GetTempFileName();
        try
        {
            using var env = new EnvVarScope("GHIDRASHARP_SERVER_DIR", envDir);
            var args = GhidraServer.BuildLaunchArgs(new GhidraServerOptions { ArgFile = argFile });
            Assert.Equal("@" + Path.GetFullPath(argFile), args[^1]);
            Assert.DoesNotContain("-cp", args);
        }
        finally
        {
            File.Delete(argFile);
            Directory.Delete(envDir, recursive: true);
        }
    }
}
