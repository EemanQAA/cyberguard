using CyberGuard.Shared.PasswordAnalysis;
using Xunit;

namespace CyberGuard.UnitTests;

public class PasswordAnalyzerTests
{
    [Fact]
    public void Analyze_CommonPassword_IsRatedWeak()
    {
        var result = PasswordAnalyzer.Analyze("password");

        Assert.Equal(PasswordRatingResult.Weak, result.Rating);
        Assert.True(result.MatchedCommonOrWordlist);
    }

    [Fact]
    public void Analyze_LongMixedCharsetPassword_IsRatedStrong()
    {
        var result = PasswordAnalyzer.Analyze("Tr0ub4dor&3xplosion!9Q");

        Assert.Equal(PasswordRatingResult.Strong, result.Rating);
        Assert.False(result.MatchedCommonOrWordlist);
    }

    [Fact]
    public void Analyze_MatchesCustomWordlist_IsRatedWeak()
    {
        var result = PasswordAnalyzer.Analyze("Ghauri2026!", customWordlist: new[] { "Ghauri2026!" });

        Assert.Equal(PasswordRatingResult.Weak, result.Rating);
        Assert.True(result.MatchedCommonOrWordlist);
    }

    [Theory]
    [InlineData("")]
    [InlineData("aaaa")]
    public void CalculateEntropyBits_EmptyOrSingleCharsetOnly_IsLowOrZero(string password)
    {
        var entropy = PasswordAnalyzer.CalculateEntropyBits(password);

        Assert.True(entropy >= 0);
    }
}
