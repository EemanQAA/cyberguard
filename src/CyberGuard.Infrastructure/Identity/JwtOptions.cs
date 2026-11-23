namespace CyberGuard.Infrastructure.Identity;

public class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; set; } = "CyberGuard";
    public string Audience { get; set; } = "CyberGuard.Clients";

    /// <summary>
    /// HS256 signing key. Set this from configuration/user-secrets/environment variable
    /// in every environment - never commit a real value. Must be at least 32 characters.
    /// </summary>
    public string SigningKey { get; set; } = default!;

    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    public int RefreshTokenLifetimeDays { get; set; } = 7;
}
