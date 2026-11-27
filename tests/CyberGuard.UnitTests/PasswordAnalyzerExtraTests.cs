using CyberGuard.Shared.PasswordAnalysis;
using Xunit;

namespace CyberGuard.UnitTests;

/// <summary>
/// Extra tests for the password strength engine (SCRUM-18). Covers rating bands,
/// each rule flag, the entropy formula, and the custom wordlist.
/// </summary>
public class PasswordAnalyzerExtraTests
{
    [Fact]
    public void Analyze_NullPassword_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => PasswordAnalyzer.Analyze(null!));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("PASSWORD")]
    [InlineData("Qwerty")]
    [InlineData("123456")]
    public void Analyze_CommonPasswordsInAnyCase_AreWeak(string password)
    {
        var result = PasswordAnalyzer.Analyze(password);

        Assert.True(result.MatchedCommonOrWordlist);
        Assert.Equal(PasswordRatingResult.Weak, result.Rating);
    }

    [Fact]
    public void Analyze_CustomWordlistMatch_IsCaseInsensitiveAndWeak()
    {
        var result = PasswordAnalyzer.Analyze("Zoya2026!", new[] { "zoya2026!" });

        Assert.True(result.MatchedCommonOrWordlist);
        Assert.Equal(PasswordRatingResult.Weak, result.Rating);
    }

    [Fact]
    public void Analyze_WordlistThatDoesNotMatch_DoesNotForceWeak()
    {
        var result = PasswordAnalyzer.Analyze("Tr0ub4dor&3xplosion!9Q", new[] { "somethingelse" });

        Assert.False(result.MatchedCommonOrWordlist);
        Assert.Equal(PasswordRatingResult.Strong, result.Rating);
    }

    [Fact]
    public void Analyze_LowercaseOnlyEightChars_IsWeakBecauseEntropyBelowForty()
    {
        // 8 * log2(26) = about 37.6 bits
        var result = PasswordAnalyzer.Analyze("abcdefgh");

        Assert.Equal(PasswordRatingResult.Weak, result.Rating);
    }

    [Fact]
    public void Analyze_MixedCaseEightChars_IsFair()
    {
        // 8 * log2(52) = about 45.6 bits, between 40 and 60
        var result = PasswordAnalyzer.Analyze("Abcdefgh");

        Assert.False(result.MatchedCommonOrWordlist);
        Assert.Equal(PasswordRatingResult.Fair, result.Rating);
    }

    [Fact]
    public void Analyze_ShortPassword_FailsMinLengthRule()
    {
        var result = PasswordAnalyzer.Analyze("Ab1!");

        Assert.False(result.HasMinLength);
    }

    [Fact]
    public void Analyze_ThirteenCharPassword_PassesMinLengthRule()
    {
        var result = PasswordAnalyzer.Analyze("Abcdefgh1!xyz");

        Assert.True(result.HasMinLength);
    }

    [Fact]
    public void Analyze_ReportsEachCharacterClass()
    {
        var all = PasswordAnalyzer.Analyze("aB3$");
        Assert.True(all.HasUpperAndLower);
        Assert.True(all.HasDigit);
        Assert.True(all.HasSymbol);

        var lettersOnly = PasswordAnalyzer.Analyze("abcdef");
        Assert.False(lettersOnly.HasUpperAndLower);
        Assert.False(lettersOnly.HasDigit);
        Assert.False(lettersOnly.HasSymbol);
    }

    [Fact]
    public void Analyze_FourSameCharactersInARow_IsFlaggedAsRepeatedPattern()
    {
        var result = PasswordAnalyzer.Analyze("aaaaXyz1!");

        Assert.False(result.NoRepeatedPatterns);
    }

    [Fact]
    public void Analyze_RepeatedSubstring_IsFlaggedAsRepeatedPattern()
    {
        var result = PasswordAnalyzer.Analyze("Xabab9!Q");

        Assert.False(result.NoRepeatedPatterns);
    }

    [Fact]
    public void Analyze_NoRepeats_PassesRepeatedPatternRule()
    {
        var result = PasswordAnalyzer.Analyze("Tr0ub4dor&3xplosion!9Q");

        Assert.True(result.NoRepeatedPatterns);
    }

    [Fact]
    public void CalculateEntropyBits_Lowercase_UsesPoolOf26()
    {
        Assert.Equal(3 * Math.Log2(26), PasswordAnalyzer.CalculateEntropyBits("abc"), 5);
    }

    [Fact]
    public void CalculateEntropyBits_Digits_UsesPoolOf10()
    {
        Assert.Equal(4 * Math.Log2(10), PasswordAnalyzer.CalculateEntropyBits("1234"), 5);
    }

    [Fact]
    public void CalculateEntropyBits_AllFourClasses_UsesPoolOf94()
    {
        Assert.Equal(4 * Math.Log2(94), PasswordAnalyzer.CalculateEntropyBits("aA1!"), 5);
    }

    [Fact]
    public void CalculateEntropyBits_Empty_IsZero()
    {
        Assert.Equal(0, PasswordAnalyzer.CalculateEntropyBits(""));
    }

    [Fact]
    public void CalculateEntropyBits_LongerPasswordHasMoreEntropy()
    {
        var shorter = PasswordAnalyzer.CalculateEntropyBits("aA1!aA1!");
        var longer = PasswordAnalyzer.CalculateEntropyBits("aA1!aA1!aA1!");

        Assert.True(longer > shorter);
    }
}
