namespace CyberGuard.Domain.Engines;

/// <summary>
/// Turns a raw URL into a fixed set of numeric features for the ML phishing model
/// (SCRUM-7 / SCRUM-26). Pure, framework-free and deterministic: the server never fetches
/// the URL, every feature is computed from the string alone.
///
/// IMPORTANT: the feature names and their meaning must stay identical to
/// ml/features.py (Zoya's training pipeline). If you add or change a feature here,
/// change it there too, otherwise the model sees different inputs in training and in
/// production ("training/serving skew").
/// </summary>
public static class UrlFeatureExtractor
{
    /// <summary>Stable feature order. The ONNX model expects the values in exactly this order.</summary>
    public static readonly IReadOnlyList<string> FeatureNames = new[]
    {
        "url_length",
        "host_length",
        "num_dots",
        "num_hyphens",
        "num_digits",
        "digit_ratio",
        "num_subdomains",
        "is_https",
        "has_at_symbol",
        "has_ip_host",
        "has_punycode",
        "num_query_params",
        "path_depth",
        "special_char_count",
        "has_suspicious_keyword"
    };

    private static readonly string[] SuspiciousKeywords =
    {
        "login", "verify", "secure", "update", "confirm", "account", "signin", "banking"
    };

    /// <summary>
    /// Extracts all features. Always returns every key in <see cref="FeatureNames"/>.
    /// If the URL cannot be parsed, only url_length is set and the rest are 0.
    /// </summary>
    public static IReadOnlyDictionary<string, float> Extract(string rawUrl)
    {
        ArgumentNullException.ThrowIfNull(rawUrl);

        var features = FeatureNames.ToDictionary(name => name, _ => 0f);
        features["url_length"] = rawUrl.Length;

        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return features;
        }

        var host = uri.Host;
        var digitCount = rawUrl.Count(char.IsDigit);
        var isIpHost = System.Text.RegularExpressions.Regex.IsMatch(host, @"^\d{1,3}(\.\d{1,3}){3}$");

        features["host_length"] = host.Length;
        features["num_dots"] = rawUrl.Count(c => c == '.');
        features["num_hyphens"] = rawUrl.Count(c => c == '-');
        features["num_digits"] = digitCount;
        features["digit_ratio"] = rawUrl.Length == 0 ? 0f : (float)digitCount / rawUrl.Length;
        // An IP address has dots but no subdomains, so it counts as 0.
        features["num_subdomains"] = isIpHost ? 0f : Math.Max(0, host.Split('.').Length - 2);
        features["is_https"] = string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase) ? 1f : 0f;
        features["has_at_symbol"] = rawUrl.Contains('@') ? 1f : 0f;
        features["has_ip_host"] = isIpHost ? 1f : 0f;
        features["has_punycode"] = host.Contains("xn--", StringComparison.OrdinalIgnoreCase) ? 1f : 0f;
        features["num_query_params"] = string.IsNullOrEmpty(uri.Query)
            ? 0f
            : uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Length;
        features["path_depth"] = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Length;
        features["special_char_count"] = rawUrl.Count(c => !char.IsLetterOrDigit(c));
        features["has_suspicious_keyword"] =
            SuspiciousKeywords.Any(k => rawUrl.Contains(k, StringComparison.OrdinalIgnoreCase)) ? 1f : 0f;

        return features;
    }
}
