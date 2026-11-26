
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

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
/// Heuristic phishing URL risk detection engine (SCRUM-23).
/// Evaluates URL strings without making network requests.
/// </summary>
public static class UrlRiskEngine
{
    private static readonly string[] SuspiciousKeywords =
    {
        "login", "verify", "secure", "update",
        "confirm", "account", "signin", "banking"
    };

    private static readonly string[] WellKnownBrands =
    {
        "paypal.com", "google.com", "microsoft.com",
        "apple.com", "amazon.com", "facebook.com",
        "instagram.com", "netflix.com",
        "bankofamerica.com"
    };

    private static readonly string[] SuspiciousTlds =
    {
        ".zip", ".xyz", ".top"
    };

    public static UrlRiskResult Evaluate(string rawUrl)
    {
        var reasons = new List<UrlRiskReason>();

        // Rule 1: Validate URL
        if (string.IsNullOrWhiteSpace(rawUrl) ||
            !Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp &&
             uri.Scheme != Uri.UriSchemeHttps) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return new UrlRiskResult(100, new[]
            {
                new UrlRiskReason(
                    "invalid-url",
                    "The URL is invalid or unsupported.",
                    100)
            });
        }

        string host = uri.Host.ToLowerInvariant();

        // Rule 2: Check HTTPS
        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            reasons.Add(new UrlRiskReason(
                "no-https",
                "Connection is not HTTPS.",
                20));
        }

        // Rule 3: Detect raw IP addresses
        bool isIpHost = IPAddress.TryParse(host, out _);

        if (isIpHost)
        {
            reasons.Add(new UrlRiskReason(
                "ip-host",
                "Host is a raw IP address.",
                25));
        }

        // Rule 4: Detect @ trick
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            reasons.Add(new UrlRiskReason(
                "at-trick",
                "URL contains the @ trick.",
                30));
        }

        // Rule 5: Detect excessive subdomains
        // IP addresses must not be treated as subdomains.
        int labelCount = host.Split('.').Length;

        if (!isIpHost && labelCount >= 4)
        {
            reasons.Add(new UrlRiskReason(
                "many-subdomains",
                "Excessive number of subdomains.",
                15));
        }

        // Rule 6: Detect long URLs
        if (rawUrl.Length > 90)
        {
            reasons.Add(new UrlRiskReason(
                "long-url",
                "Unusually long URL.",
                10));
        }

        // Rule 7: Detect punycode
        if (host.Contains("xn--",
            StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add(new UrlRiskReason(
                "punycode",
                "Host uses punycode (possible look-alike characters).",
                25));
        }

        // Rule 8: Detect suspicious keywords
        if (SuspiciousKeywords.Any(keyword =>
            rawUrl.Contains(
                keyword,
                StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add(new UrlRiskReason(
                "suspicious-keyword",
                "Contains a suspicious keyword.",
                10));
        }

        // Rule 9: Detect typosquatting
        var typosquat = WellKnownBrands.FirstOrDefault(
            brand => IsCloseTyposquat(host, brand));

        if (typosquat != null)
        {
            reasons.Add(new UrlRiskReason(
                "typosquat",
                $"Looks like a typosquat of {typosquat}.",
                35));
        }

        // Rule 10: Detect brand impersonation
        // Example: paypal.com.evil.example
        var impersonatedBrand = WellKnownBrands.FirstOrDefault(
            brand =>
                !host.Equals(
                    brand,
                    StringComparison.OrdinalIgnoreCase) &&
                !host.EndsWith(
                    "." + brand,
                    StringComparison.OrdinalIgnoreCase) &&
                (host.StartsWith(
                    brand + ".",
                    StringComparison.OrdinalIgnoreCase) ||
                 host.Contains(
                    "." + brand + ".",
                    StringComparison.OrdinalIgnoreCase)));

        if (impersonatedBrand != null)
        {
            reasons.Add(new UrlRiskReason(
                "brand-impersonation",
                $"URL appears to impersonate {impersonatedBrand}.",
                35));
        }

        // Rule 11: Detect suspicious TLDs
        if (!isIpHost && SuspiciousTlds.Any(tld =>
            host.EndsWith(
                tld,
                StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add(new UrlRiskReason(
                "suspicious-tld",
                "Domain uses a potentially suspicious TLD.",
                15));
        }

        // Calculate final score (maximum 100)
        int score = Math.Min(
            100,
            reasons.Sum(reason => reason.Weight));

        return new UrlRiskResult(score, reasons);
    }

    private static bool IsCloseTyposquat(
        string host,
        string brandDomain)
    {
        // Do not flag legitimate brand domains.
        if (host.Equals(
            brandDomain,
            StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Do not flag legitimate subdomains.
        if (host.EndsWith(
            "." + brandDomain,
            StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int distance = LevenshteinDistance(
            host,
            brandDomain);

        return distance > 0 && distance <= 2;
    }

    private static int LevenshteinDistance(
        string a,
        string b)
    {
        int[,] dp = new int[a.Length + 1, b.Length + 1];

        for (int i = 0; i <= a.Length; i++)
        {
            dp[i, 0] = i;
        }

        for (int j = 0; j <= b.Length; j++)
        {
            dp[0, j] = j;
        }

        for (int i = 1; i <= a.Length; i++)
        {
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;

                dp[i, j] = Math.Min(
                    Math.Min(
                        dp[i - 1, j] + 1,
                        dp[i, j - 1] + 1),
                    dp[i - 1, j - 1] + cost);
            }
        }

        return dp[a.Length, b.Length];
    }
}
