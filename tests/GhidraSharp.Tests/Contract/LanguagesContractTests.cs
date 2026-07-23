namespace Const24.GhidraSharp.Tests.Contract;

public sealed class LanguagesContractTests(HappyServerFixture fixture) : IClassFixture<HappyServerFixture>
{
    private GhidraClient Client => fixture.Client;

    [Fact]
    public async Task ListLanguages_maps_each_descriptor_to_GhidraLanguage()
    {
        var langs = await Client.ListLanguagesAsync(ct: TestContext.Current.CancellationToken);

        var l = Assert.Single(langs);
        Assert.Equal("SuperH:BE:32:SH-2A", l.Id);
        Assert.Equal("SuperH", l.Processor);
        Assert.Equal("big", l.Endian);
        Assert.Equal(32, l.Size);
        Assert.Equal("SH-2A", l.Variant);
    }
}
