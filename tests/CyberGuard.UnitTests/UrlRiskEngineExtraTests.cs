using CyberGuard.Domain.Engines;
using Xunit;

namespace CyberGuard.UnitTests;

/// <summary>
/// Extra tests for the heuristic URL rules (SCRUM-23). One test per rule so a failing
/// test tells you exactly which rule broke.
/// </summary>
public class UrlRiskEngineExtraTests
{
    [Fact]
    public void Evaluate_UnparseableText_IsScoredHundredWithInvalidUrlReason()
    {
        var result = UrlRiskEngine.Evaluate("not a url");

        Assert.Equal(100, result.Score);
        Assert.Equal("High", result.Label);
        Assert.Contains(result.Reasons, r => r.Code == "invalid-url");
    }

    [Fact]
    public void Evaluate_PlainHttpsSite_HasZeroRisk()
    {
        var result = UrlRiskEngine.Evaluate("https://example.org/");

        Assert.Equal(0, result.Score);
        Assert.Empty(result.Reasons);
        Assert.Equal("Low", result.Label);
    }

    [Fact]
    public void Evaluate_HttpOnly_FlagsNoHttpsAndStaysLowRisk()
    {
        var result = UrlRiskEngine.Evaluate("http://example.org/");

        Assert.Contains(result.Reasons, r => r.Code == "no-https");
        Assert.Equal(20, result.Score);
        Assert.Equal("Low", result.Label);
    }

    [Fact]
    public void Evaluate_ManySubdomains_FlagsManySubdomains()
    {
        var result = UrlRiskEngine.Evaluate("https://a.b.c.example.org/");

        Assert.Contains(result.Reasons, r => r.Code == "many-subdomains");
    }

    [Fact]
    public void Evaluate_VeryLongUrl_FlagsLongUrl()
    {
        var result = UrlRiskEngine.Evaluate("https://example.org/" + new string('a', 100));

        Assert.Contains(result.Reasons, r => r.Code == "long-url");
    }

    [Fact]
    public void Evaluate_PunycodeHost_FlagsPunycode()
    {
        var result = UrlRiskEngine.Evaluate("https://xn--pple-43d.com/");

        Assert.Contains(result.Reasons, r => r.Code == "punycode");
    }

    [Fact]
    public void Evaluate_SuspiciousKeywordInPath_FlagsKeyword()
    {
        var result = UrlRiskEngine.Evaluate("https://example.org/login");

        Assert.Contains(result.Reasons, r => r.Code == "suspicious-keyword");
    }

    [Fact]
    public void Evaluate_RealBrandDomain_IsNotATyposquat()
    {
        var result = UrlRiskEngine.Evaluate("https://google.com/");

        Assert.DoesNotContain(result.Reasons, r => r.Code == "typosquat");
    }

    [Fact]
    public void Evaluate_OneLetterOffBrand_IsATyposquat()
    {
        var result = UrlRiskEngine.Evaluate("https://goggle.com/");

        Assert.Contains(result.Reasons, r => r.Code == "typosquat");
    }

    [Fact]
    public void Evaluate_ManyRulesTriggered_IsHighRiskAndCappedAtHundred()
    {
        var url = "http://paypal.com@a.b.c.d.evil.example/login/" + new string('x', 100);

        var result = UrlRiskEngine.Evaluate(url);

        Assert.Equal("High", result.Label);
        Assert.InRange(result.Score, 70, 100);
    }

    [Theory]
    [InlineData(0, "Low")]
    [InlineData(39, "Low")]
    [InlineData(40, "Medium")]
    [InlineData(69, "Medium")]
    [InlineData(70, "High")]
    [InlineData(100, "High")]
    public void Label_MapsScoreToBand(int score, string expectedLabel)
    {
        var result = new UrlRiskResult(score, Array.Empty<UrlRiskReason>());

        Assert.Equal(expectedLabel, result.Label);
    }
}
