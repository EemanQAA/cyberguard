using CyberGuard.Domain.Enums;

namespace CyberGuard.Domain.Entities;

/// <summary>
/// A phishing-URL scan result. RiskScore is 0-100 (Low 0-39, Medium 40-69, High 70-100).
/// The server never fetches the URL itself - only DNS resolution and static heuristics.
/// </summary>
public class UrlScan
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Url { get; set; } = default!;
    public int RiskScore { get; set; }
    public string ReasonsJson { get; set; } = "[]";
    public UrlVerdict Verdict { get; set; } = UrlVerdict.Unknown;
    public Guid ModelVersionId { get; set; }
    public Guid? IpGeolocationId { get; set; }
    public DateTimeOffset ScannedAt { get; set; } = DateTimeOffset.UtcNow;

    public void SetVerdict(UrlVerdict verdict)
    {
        if (verdict == UrlVerdict.Unknown)
        {
            throw new InvalidOperationException("A verdict must be Safe or Phishing.");
        }

        Verdict = verdict;
    }
}
