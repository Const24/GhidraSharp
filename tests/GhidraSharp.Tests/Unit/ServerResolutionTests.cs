namespace Const24.GhidraSharp.Tests.Unit;

public class ServerResolutionTests
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
        var prev = Environment.GetEnvironmentVariable("GHIDRASHARP_SERVER_DIR");
        try
        {
            Environment.SetEnvironmentVariable("GHIDRASHARP_SERVER_DIR", tmp);
            Assert.Equal(Path.GetFullPath(tmp), GhidraServer.ResolveServerDirectory(new GhidraServerOptions()));
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRASHARP_SERVER_DIR", prev);
            Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void A_GHIDRASHARP_SERVER_DIR_without_a_lib_folder_is_ignored()
    {
        var tmp = Directory.CreateTempSubdirectory("ghs_srv_").FullName; // no lib/
        var prev = Environment.GetEnvironmentVariable("GHIDRASHARP_SERVER_DIR");
        try
        {
            Environment.SetEnvironmentVariable("GHIDRASHARP_SERVER_DIR", tmp);
            // no lib/ in the env dir, and the test host has no server folder beside it
            Assert.Null(GhidraServer.ResolveServerDirectory(new GhidraServerOptions()));
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRASHARP_SERVER_DIR", prev);
            Directory.Delete(tmp, recursive: true);
        }
    }
}
