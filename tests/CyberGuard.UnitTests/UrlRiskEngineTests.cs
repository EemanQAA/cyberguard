using CyberGuard.Domain.Engines;
using Xunit;

namespace CyberGuard.UnitTests;

public class UrlRiskEngineTests
{
    [Fact]
    public void Evaluate_HttpsKnownBrand_IsLowRisk()
    {
        var result = UrlRiskEngine.Evaluate("https://www.google.com/search?q=test");

        Assert.Equal("Low", result.Label);
    }

    [Fact]
    public void Evaluate_RawIpHost_FlagsIpHostReason()
    {
        var result = UrlRiskEngine.Evaluate("http://192.168.1.10/login");

        Assert.Contains(result.Reasons, r => r.Code == "ip-host");
        Assert.Contains(result.Reasons, r => r.Code == "no-https");
    }

    [Fact]
    public void Evaluate_AtTrick_FlagsAtTrickReason()
    {
        var result = UrlRiskEngine.Evaluate("https://paypal.com@malicious-site.example/verify");

        Assert.Contains(result.Reasons, r => r.Code == "at-trick");
    }

    [Fact]
    public void Evaluate_Typosquat_FlagsTyposquatReason()
    {
        var result = UrlRiskEngine.Evaluate("https://paypa1.com/login");

        Assert.Contains(result.Reasons, r => r.Code == "typosquat");
    }
}
