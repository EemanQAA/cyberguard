using CyberGuard.Domain.Engines;
using Xunit;

namespace CyberGuard.UnitTests;

/// <summary>
/// Tests for the PII / secret scanner (SCRUM-27, SCRUM-32). Important rule: findings
/// must always be masked, the raw secret must never appear in a finding.
/// </summary>
public class PiiDetectorTests
{
    [Fact]
    public void Scan_PlainText_FindsNothing()
    {
        var findings = PiiDetector.Scan("Hello world, nothing sensitive here.");

        Assert.Empty(findings);
    }

    [Fact]
    public void Scan_Email_IsFoundAndMasked()
    {
        var findings = PiiDetector.Scan("contact me at john.doe@example.com please");

        var email = Assert.Single(findings, f => f.Type == "Email");
        Assert.Equal("j******e@example.com", email.Masked);
        Assert.DoesNotContain("john.doe", email.Masked);
    }

    [Fact]
    public void Scan_VeryShortEmail_IsFullyHiddenBeforeTheAt()
    {
        var findings = PiiDetector.Scan("a@b.co");

        var email = Assert.Single(findings, f => f.Type == "Email");
        Assert.Equal("***@b.co", email.Masked);
    }

    [Fact]
    public void Scan_PakistaniMobileNumber_IsFoundAndOnlyLastTwoDigitsVisible()
    {
        var findings = PiiDetector.Scan("call +92 300 1234567 now");

        var phone = Assert.Single(findings, f => f.Type == "Phone");
        Assert.EndsWith("67", phone.Masked);
        Assert.DoesNotContain("1234567", phone.Masked);
    }

    [Fact]
    public void Scan_Cnic_IsFoundAndMiddleIsMasked()
    {
        var findings = PiiDetector.Scan("CNIC 35202-1234567-1");

        var cnic = Assert.Single(findings, f => f.Type == "CNIC");
        Assert.StartsWith("35", cnic.Masked);
        Assert.EndsWith("-1", cnic.Masked);
        Assert.Contains("*", cnic.Masked);
        Assert.DoesNotContain("1234567", cnic.Masked);
    }

    [Fact]
    public void Scan_ValidCardNumber_IsFoundAndOnlyLastFourVisible()
    {
        var findings = PiiDetector.Scan("card 4111 1111 1111 1111");

        var card = Assert.Single(findings, f => f.Type == "Card (Luhn valid)");
        Assert.Equal("************1111", card.Masked);
    }

    [Fact]
    public void Scan_CardNumberFailingLuhn_IsIgnored()
    {
        var findings = PiiDetector.Scan("card 4111 1111 1111 1112");

        Assert.DoesNotContain(findings, f => f.Type.StartsWith("Card"));
    }

    [Fact]
    public void Scan_AwsAccessKey_IsFoundAndMasked()
    {
        var findings = PiiDetector.Scan("key=AKIAIOSFODNN7EXAMPLE");

        var key = Assert.Single(findings, f => f.Type == "AWS access key");
        Assert.EndsWith("MPLE", key.Masked);
        Assert.DoesNotContain("AKIA", key.Masked);
    }

    [Fact]
    public void Scan_Jwt_IsFoundAndMasked()
    {
        var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123_-xyz";

        var findings = PiiDetector.Scan("token: " + jwt);

        var found = Assert.Single(findings, f => f.Type == "JWT");
        Assert.DoesNotContain("eyJhbGci", found.Masked);
    }

    [Fact]
    public void Scan_TextWithSeveralSecrets_FindsAllOfThem()
    {
        var text = "mail a@b.co and AKIAIOSFODNN7EXAMPLE and 35202-1234567-1";

        var findings = PiiDetector.Scan(text);

        Assert.Contains(findings, f => f.Type == "Email");
        Assert.Contains(findings, f => f.Type == "AWS access key");
        Assert.Contains(findings, f => f.Type == "CNIC");
    }

    [Fact]
    public void Scan_NoFindingEverContainsTheRawInput()
    {
        var raw = "AKIAIOSFODNN7EXAMPLE";

        var findings = PiiDetector.Scan(raw);

        Assert.All(findings, f => Assert.NotEqual(raw, f.Masked));
    }
}
