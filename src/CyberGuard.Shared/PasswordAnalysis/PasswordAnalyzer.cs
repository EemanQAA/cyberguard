namespace CyberGuard.Shared.PasswordAnalysis;

public enum PasswordRatingResult
{
    Weak,
    Fair,
    Strong
}

public record PasswordAnalysisResult(
    double EntropyBits,
    PasswordRatingResult Rating,
    bool MatchedCommonOrWordlist,
    bool HasMinLength,
    bool HasUpperAndLower,
    bool HasDigit,
    bool HasSymbol,
    bool NoRepeatedPatterns);

/// <summary>
/// Shared password-strength engine. Intended to run entirely on the client (browser
/// WebAssembly or MAUI) so the raw password never reaches the API - only the result of
/// <see cref="Analyze"/> is sent over the wire. See design doc Section 3.1 / Table 2.
/// </summary>
public static class PasswordAnalyzer
{
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "123456", "123456789", "qwerty", "letmein", "111111",
        "abc123", "password1", "iloveyou", "admin", "welcome", "monkey"
    };

    public static PasswordAnalysisResult Analyze(string password, IEnumerable<string>? customWordlist = null)
    {
        ArgumentNullException.ThrowIfNull(password);

        var hasLower = password.Any(char.IsLower);
        var hasUpper = password.Any(char.IsUpper);
        var hasDigit = password.Any(char.IsDigit);
        var hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));
        var hasMinLength = password.Length >= 12;
        var noRepeated = !HasRepeatedPattern(password);

        var matched = CommonPasswords.Contains(password) ||
                      (customWordlist?.Any(w => string.Equals(w, password, StringComparison.OrdinalIgnoreCase)) ?? false);

        var entropy = CalculateEntropyBits(password);

        var rating = matched || entropy < 40
            ? PasswordRatingResult.Weak
            : entropy < 60
                ? PasswordRatingResult.Fair
                : PasswordRatingResult.Strong;

        return new PasswordAnalysisResult(
            entropy,
            rating,
            matched,
            hasMinLength,
            hasUpper && hasLower,
            hasDigit,
            hasSymbol,
            noRepeated);
    }

    public static double CalculateEntropyBits(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return 0;
        }

        var poolSize = 0;
        if (password.Any(char.IsLower)) poolSize += 26;
        if (password.Any(char.IsUpper)) poolSize += 26;
        if (password.Any(char.IsDigit)) poolSize += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) poolSize += 32;

        if (poolSize == 0)
        {
            return 0;
        }

        return password.Length * Math.Log2(poolSize);
    }

    private static bool HasRepeatedPattern(string password)
    {
        // Flags simple repeated-character runs (e.g. "aaaa") and short repeated
        // substrings (e.g. "abab", "123123"). Not exhaustive - a starting point
        // for Sprint 2 to extend with keyboard-walk detection.
        for (var i = 0; i + 3 < password.Length; i++)
        {
            if (password[i] == password[i + 1] && password[i + 1] == password[i + 2] && password[i + 2] == password[i + 3])
            {
                return true;
            }
        }

        for (var len = 2; len <= password.Length / 2; len++)
        {
            for (var i = 0; i + 2 * len <= password.Length; i++)
            {
                if (password.Substring(i, len) == password.Substring(i + len, len))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
