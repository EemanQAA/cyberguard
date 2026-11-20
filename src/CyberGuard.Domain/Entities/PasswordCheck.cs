using CyberGuard.Domain.Enums;

namespace CyberGuard.Domain.Entities;

/// <summary>
/// A saved result of the client-side password analysis engine (CyberGuard.Shared).
/// The password itself never reaches the API - only the score, entropy and rating are sent.
/// </summary>
public class PasswordCheck
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public double EntropyBits { get; set; }
    public PasswordRating Rating { get; set; }
    public bool MatchedCommonOrWordlist { get; set; }
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.UtcNow;
}
