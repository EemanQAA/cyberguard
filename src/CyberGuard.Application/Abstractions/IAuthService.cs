using CyberGuard.Application.Features.Auth;

namespace CyberGuard.Application.Abstractions;

/// <summary>
/// Contract for the Users/Auth module (UC-01, UC-02, UC-03). Implemented in
/// CyberGuard.Infrastructure.Identity.AuthService using ASP.NET Core Identity + JWT.
/// </summary>
public interface IAuthService
{
    Task<AuthResult<UserProfileDto>> RegisterAsync(RegisterRequest request, CancellationToken ct = default);

    Task<AuthResult<AuthTokensResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default);

    Task<AuthResult<AuthTokensResponse>> RefreshAsync(string refreshToken, CancellationToken ct = default);

    Task LogoutAsync(string refreshToken, CancellationToken ct = default);

    Task<UserProfileDto?> GetProfileAsync(Guid userId, CancellationToken ct = default);

    Task<AuthResult<UserProfileDto>> UpdateProfileAsync(Guid userId, UpdateProfileRequest request, CancellationToken ct = default);

    Task DeleteAccountAsync(Guid userId, CancellationToken ct = default);
}
