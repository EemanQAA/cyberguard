namespace CyberGuard.Domain.Entities;

/// <summary>
/// A bookmarked scan result with an optional user note. Refers to exactly one scan
/// (Table 9 CHECK constraint: num_nonnulls(PasswordCheckId, UrlScanId, PiiScanId) = 1).
/// </summary>
public class SavedReport
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid? PasswordCheckId { get; set; }
    public Guid? UrlScanId { get; set; }
    public Guid? PiiScanId { get; set; }
    public string? Note { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public int ReferencedScanCount =>
        (PasswordCheckId.HasValue ? 1 : 0) +
        (UrlScanId.HasValue ? 1 : 0) +
        (PiiScanId.HasValue ? 1 : 0);
}
