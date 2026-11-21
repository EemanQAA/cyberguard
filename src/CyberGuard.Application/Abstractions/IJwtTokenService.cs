namespace CyberGuard.Application.Abstractions;

public record GeneratedAccessToken(string Token, DateTimeOffset ExpiresAt);

/// <summary>
/// Issues short-lived JWT access tokens. Sprint 1 uses a symmetric HS256 signing key
/// (simplest to get right first); the design doc's ES256 key-rotation scheme (Table 13)
/// is a drop-in upgrade for a later sprint - only this implementation would change.
/// </summary>
public interface IJwtTokenService
{
    GeneratedAccessToken GenerateAccessToken(Guid userId, string email);

    string GenerateRefreshTokenRaw();

    string HashRefreshToken(string rawToken);
}
