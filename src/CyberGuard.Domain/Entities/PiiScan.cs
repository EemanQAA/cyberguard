namespace CyberGuard.Domain.Entities;

/// <summary>
/// A PII/secret-leak scan result. The pasted text itself is analysed in memory and
/// discarded - only the masked findings (as JSON) are ever persisted.
/// </summary>
public class PiiScan
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string MaskedFindingsJson { get; set; } = "[]";
    public int FindingCount { get; set; }
    public DateTimeOffset ScannedAt { get; set; } = DateTimeOffset.UtcNow;
}
