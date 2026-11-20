using System.Text.RegularExpressions;

namespace CyberGuard.Domain.Engines;

public record UrlRiskReason(string Code, string Message, int Weight);

public record UrlRiskResult(int Score, IReadOnlyList<UrlRiskReason> Reasons)
{
    public string Label => Score switch
    {
        >= 70 => "High",
        >= 40 => "Medium",
        _ => "Low"
    };
}

/// <summary>
/// Pure, framework-free static heuristics for the phishing URL scanner (UC-05).
/// The server never fetches the URL - every rule works from the string alone plus,
/// optionally, the resolved IP. ML scoring (Sprint 3+) sits alongside this as a
/// separate IPhishingModel and the two are combined by the Application-layer scan service.
/// Strategy pattern: each rule is an independent static check - add a new one without
/// touching the others (Open/Closed principle, Section 5 design decision).
/// </summary>
public static class UrlRiskEngine
{
    private static readonly string[] SuspiciousKeywords =
    {
        "login", "verify", "secure", "update", "confirm", "account", "signin", "banking"
    };

    private static readonly string[] WellKnownBrands =
    {
        "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
        "facebook.com", "instagram.com", "netflix.com", "bankofamerica.com"
    };

    public static UrlRiskResult Evaluate(string rawUrl)
    {
        var reasons = new List<UrlRiskReason>();

        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return new UrlRiskResult(100, new[] { new UrlRiskReason("invalid-url", "The URL could not be parsed.", 100) });
        }

        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add(new UrlRiskReason("no-https", "Connection is not HTTPS.", 20));
        }

        if (Regex.IsMatch(uri.Host, @"^\d{1,3}(\.\d{1,3}){3}$"))
        {
            reasons.Add(new UrlRiskReason("ip-host", "Host is a raw IP address.", 25));
        }

        if (rawUrl.Contains('@'))
        {
            reasons.Add(new UrlRiskReason("at-trick", "URL contains the \"@\" trick.", 30));
        }

        var labelCount = uri.Host.Split('.').Length;
        if (labelCount >= 4)
        {
            reasons.Add(new UrlRiskReason("many-subdomains", "Excessive number of subdomains.", 15));
        }

        if (rawUrl.Length > 90)
        {
            reasons.Add(new UrlRiskReason("long-url", "Unusually long URL.", 10));
        }

        if (uri.Host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add(new UrlRiskReason("punycode", "Host uses punycode (possible look-alike characters).", 25));
        }

        if (SuspiciousKeywords.Any(k => rawUrl.Contains(k, StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add(new UrlRiskReason("suspicious-keyword", "Contains a suspicious keyword (login, verify, secure, ...).", 10));
        }

        var typosquat = WellKnownBrands.FirstOrDefault(b => IsCloseTyposquat(uri.Host, b));
        if (typosquat is not null)
        {
            reasons.Add(new UrlRiskReason("typosquat", $"Looks like a typosquat of {typosquat}.", 35));
        }

        var score = Math.Min(100, reasons.Sum(r => r.Weight));
        return new UrlRiskResult(score, reasons);
    }

    private static bool IsCloseTyposquat(string host, string brandDomain)
    {
        if (host.Equals(brandDomain, StringComparison.OrdinalIgnoreCase))
        {
            return false; // the real domain itself - not a typosquat
        }

        var distance = LevenshteinDistance(host, brandDomain);
        return distance > 0 && distance <= 2;
    }

    private static int LevenshteinDistance(string a, string b)
    {
        var dp = new int[a.Length + 1, b.Length + 1];
        for (var i = 0; i <= a.Length; i++) dp[i, 0] = i;
        for (var j = 0; j <= b.Length; j++) dp[0, j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                dp[i, j] = Math.Min(Math.Min(dp[i - 1, j] + 1, dp[i, j - 1] + 1), dp[i - 1, j - 1] + cost);
            }
        }

        return dp[a.Length, b.Length];
    }
}
