using CyberGuard.Domain.Enums;

namespace CyberGuard.Domain.Entities;

/// <summary>
/// An auto-flagged high-risk result (alert) or a system notice. State machine:
/// New -&gt; Read -&gt; Reviewed (Section 7.4 of the design doc).
/// </summary>
public class Alert
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public AlertSeverity Severity { get; set; }
    public string Message { get; set; } = default!;
    public ScanSourceType? SourceType { get; set; }
    public Guid? SourceId { get; set; }
    public AlertStatus Status { get; set; } = AlertStatus.New;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public void MarkReviewed()
    {
        if (Status == AlertStatus.Reviewed)
        {
            return;
        }

        Status = AlertStatus.Reviewed;
    }

    public void MarkRead()
    {
        if (Status == AlertStatus.New)
        {
            Status = AlertStatus.Read;
        }
    }
}
