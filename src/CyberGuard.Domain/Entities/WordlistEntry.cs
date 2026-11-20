namespace CyberGuard.Domain.Entities;

/// <summary>
/// A user's custom "weak password" wordlist entry (e.g. names, places they want flagged).
/// Unique per (UserId, lower(Word)).
/// </summary>
public class WordlistEntry
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Word { get; set; } = default!;
    public string? Category { get; set; }
    public DateTimeOffset AddedAt { get; set; } = DateTimeOffset.UtcNow;
}
