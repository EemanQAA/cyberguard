namespace CyberGuard.Domain.Entities;

/// <summary>
/// A hashed refresh token with family-based reuse detection (Table 13). Only the
/// SHA-256 hash is ever stored - never the raw token.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string TokenHash { get; set; } = default!;
    public Guid FamilyId { get; set; }
    public Guid? ReplacedById { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RevokedAt { get; set; }

    public bool IsActive => RevokedAt is null && ExpiresAt > DateTimeOffset.UtcNow;
}
