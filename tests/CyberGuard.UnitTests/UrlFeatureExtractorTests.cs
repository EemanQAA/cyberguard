using CyberGuard.Domain.Engines;
using Xunit;

namespace CyberGuard.UnitTests;

public class UrlFeatureExtractorTests
{
    [Fact]
    public void Extract_AlwaysReturnsEveryFeatureName()
    {
        var features = UrlFeatureExtractor.Extract("https://www.example.com/");

        Assert.Equal(UrlFeatureExtractor.FeatureNames.Count, features.Count);
        foreach (var name in UrlFeatureExtractor.FeatureNames)
        {
            Assert.True(features.ContainsKey(name), $"missing feature {name}");
        }
    }

    [Fact]
    public void Extract_NormalHttpsUrl_ComputesStructuralFeatures()
    {
        var url = "https://www.example.com/a/b?x=1&y=2";

        var features = UrlFeatureExtractor.Extract(url);

        Assert.Equal(url.Length, features["url_length"]);
        Assert.Equal(1f, features["is_https"]);
        Assert.Equal(1f, features["num_subdomains"]);   // "www" in www.example.com
        Assert.Equal(2f, features["num_query_params"]); // x and y
        Assert.Equal(2f, features["path_depth"]);       // /a/b
        Assert.Equal(0f, features["has_at_symbol"]);
        Assert.Equal(0f, features["has_ip_host"]);
        Assert.Equal(0f, features["has_suspicious_keyword"]);
    }

    [Fact]
    public void Extract_IpHostWithLoginKeyword_SetsFlags()
    {
        var features = UrlFeatureExtractor.Extract("http://192.168.0.1/login");

        Assert.Equal(0f, features["is_https"]);
        Assert.Equal(1f, features["has_ip_host"]);
        Assert.Equal(0f, features["num_subdomains"]); // an IP has dots but no subdomains
        Assert.Equal(1f, features["has_suspicious_keyword"]);
    }

    [Fact]
    public void Extract_AtSymbolAndPunycode_SetsFlags()
    {
        var features = UrlFeatureExtractor.Extract("https://paypal.com@xn--pple-43d.com/");

        Assert.Equal(1f, features["has_at_symbol"]);
        Assert.Equal(1f, features["has_punycode"]);
    }

    [Fact]
    public void Extract_UnparseableUrl_OnlyLengthIsSet()
    {
        var features = UrlFeatureExtractor.Extract("not a url");

        Assert.Equal(9f, features["url_length"]);
        Assert.Equal(0f, features["is_https"]);
        Assert.Equal(0f, features["host_length"]);
        Assert.Equal(0f, features["path_depth"]);
    }

    [Fact]
    public void Extract_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => UrlFeatureExtractor.Extract(null!));
    }
}
