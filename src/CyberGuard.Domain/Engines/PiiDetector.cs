using System.Text.RegularExpressions;

namespace CyberGuard.Domain.Engines;

public record PiiFinding(string Type, string Masked);

/// <summary>
/// Regex + checksum based PII/secret detectors (UC-06). Each detector is independent
/// (Strategy pattern, IPiiDetector-style) so Erum's module can add more without touching
/// the others. Operates purely on the in-memory string - the caller is responsible for
/// discarding the raw text immediately after calling <see cref="Scan"/>.
/// </summary>
public static class PiiDetector
{
    private static readonly Regex Email = new(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled);
    private static readonly Regex Phone = new(@"(\+92|0)[\s-]?3\d{2}[\s-]?\d{7}", RegexOptions.Compiled);
    private static readonly Regex Cnic = new(@"\d{5}-\d{7}-\d", RegexOptions.Compiled);
    private static readonly Regex CardCandidate = new(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.Compiled);
    private static readonly Regex AwsKey = new(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled);
    private static readonly Regex Jwt = new(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", RegexOptions.Compiled);

    public static IReadOnlyList<PiiFinding> Scan(string text)
    {
        var findings = new List<PiiFinding>();

        foreach (Match m in Email.Matches(text))
        {
            findings.Add(new PiiFinding("Email", MaskEmail(m.Value)));
        }

        foreach (Match m in Phone.Matches(text))
        {
            findings.Add(new PiiFinding("Phone", MaskTail(m.Value, 2)));
        }

        foreach (Match m in Cnic.Matches(text))
        {
            findings.Add(new PiiFinding("CNIC", MaskMiddle(m.Value)));
        }

        foreach (Match m in CardCandidate.Matches(text))
        {
            var digitsOnly = Regex.Replace(m.Value, @"\D", "");
            if (digitsOnly.Length is >= 13 and <= 19 && IsLuhnValid(digitsOnly))
            {
                findings.Add(new PiiFinding("Card (Luhn valid)", MaskTail(digitsOnly, 4)));
            }
        }

        foreach (Match m in AwsKey.Matches(text))
        {
            findings.Add(new PiiFinding("AWS access key", MaskTail(m.Value, 4)));
        }

        foreach (Match m in Jwt.Matches(text))
        {
            findings.Add(new PiiFinding("JWT", MaskTail(m.Value, 6)));
        }

        return findings;
    }

    private static bool IsLuhnValid(string digits)
    {
        var sum = 0;
        var alternate = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var n = digits[i] - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }

            sum += n;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }

    private static string MaskEmail(string email)
    {
        var at = email.IndexOf('@');
        if (at <= 1) return "***" + email[at..];
        return email[0] + new string('*', at - 2) + email[(at - 1)..];
    }

    private static string MaskTail(string value, int visible) =>
        value.Length <= visible ? value : new string('*', value.Length - visible) + value[^visible..];

    private static string MaskMiddle(string value) =>
        value.Length <= 4 ? value : value[..2] + new string('*', value.Length - 4) + value[^2..];
}
