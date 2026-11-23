using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Auth;
using CyberGuard.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Infrastructure.Identity;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IApplicationDbContext _db;
    private readonly IJwtTokenService _tokens;
    private readonly JwtOptions _jwtOptions;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        IApplicationDbContext db,
        IJwtTokenService tokens,
        Microsoft.Extensions.Options.IOptions<JwtOptions> jwtOptions)
    {
        _userManager = userManager;
        _db = db;
        _tokens = tokens;
        _jwtOptions = jwtOptions.Value;
    }

    public async Task<AuthResult<UserProfileDto>> RegisterAsync(RegisterRequest request, CancellationToken ct = default)
    {
        var existing = await _userManager.FindByEmailAsync(request.Email);
        if (existing is not null)
        {
            return AuthResult<UserProfileDto>.Failure("An account with this email already exists.");
        }

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = request.Email,
            Email = request.Email,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return AuthResult<UserProfileDto>.Failure(result.Errors.Select(e => e.Description).ToArray());
        }

        return AuthResult<UserProfileDto>.Success(new UserProfileDto(user.Id, user.Email!, user.CreatedAt));
    }

    public async Task<AuthResult<AuthTokensResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
        {
            return AuthResult<AuthTokensResponse>.Failure("Invalid email or password.");
        }

        var tokens = await IssueTokenPairAsync(user, familyId: Guid.NewGuid(), ct);
        return AuthResult<AuthTokensResponse>.Success(tokens);
    }

    public async Task<AuthResult<AuthTokensResponse>> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        var hash = _tokens.HashRefreshToken(refreshToken);
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == hash, ct);

        if (stored is null)
        {
            return AuthResult<AuthTokensResponse>.Failure("Invalid refresh token.");
        }

        if (stored.RevokedAt is not null)
        {
            // Reuse of an already-rotated token: likely theft - revoke the whole family.
            var family = await _db.RefreshTokens.Where(r => r.FamilyId == stored.FamilyId && r.RevokedAt == null).ToListAsync(ct);
            foreach (var t in family) t.RevokedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(ct);
            return AuthResult<AuthTokensResponse>.Failure("This refresh token was already used. All sessions for this account have been revoked - please log in again.");
        }

        if (stored.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return AuthResult<AuthTokensResponse>.Failure("Refresh token expired.");
        }

        var user = await _userManager.FindByIdAsync(stored.UserId.ToString());
        if (user is null)
        {
            return AuthResult<AuthTokensResponse>.Failure("Account no longer exists.");
        }

        var newTokens = await IssueTokenPairAsync(user, stored.FamilyId, ct, replaces: stored);
        return AuthResult<AuthTokensResponse>.Success(newTokens);
    }

    public async Task LogoutAsync(string refreshToken, CancellationToken ct = default)
    {
        var hash = _tokens.HashRefreshToken(refreshToken);
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == hash, ct);
        if (stored is null) return;

        stored.RevokedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);
    }

    public async Task<UserProfileDto?> GetProfileAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        return user is null ? null : new UserProfileDto(user.Id, user.Email!, user.CreatedAt);
    }

    public async Task<AuthResult<UserProfileDto>> UpdateProfileAsync(Guid userId, UpdateProfileRequest request, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return AuthResult<UserProfileDto>.Failure("Account not found.");
        }

        if (!string.IsNullOrWhiteSpace(request.Email) && request.Email != user.Email)
        {
            var setEmail = await _userManager.SetEmailAsync(user, request.Email);
            if (!setEmail.Succeeded)
            {
                return AuthResult<UserProfileDto>.Failure(setEmail.Errors.Select(e => e.Description).ToArray());
            }

            await _userManager.SetUserNameAsync(user, request.Email);
        }

        return AuthResult<UserProfileDto>.Success(new UserProfileDto(user.Id, user.Email!, user.CreatedAt));
    }

    public async Task DeleteAccountAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user is null) return;

        // All owned rows (scans, reports, alerts, wordlist, refresh tokens) cascade-delete
        // at the database level (ON DELETE CASCADE) - this is a single operation by design.
        await _userManager.DeleteAsync(user);
    }

    private async Task<AuthTokensResponse> IssueTokenPairAsync(ApplicationUser user, Guid familyId, CancellationToken ct, RefreshToken? replaces = null)
    {
        var access = _tokens.GenerateAccessToken(user.Id, user.Email!);
        var rawRefresh = _tokens.GenerateRefreshTokenRaw();
        var refreshHash = _tokens.HashRefreshToken(rawRefresh);

        var entity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = refreshHash,
            FamilyId = familyId,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_jwtOptions.RefreshTokenLifetimeDays),
            CreatedAt = DateTimeOffset.UtcNow
        };

        _db.RefreshTokens.Add(entity);

        if (replaces is not null)
        {
            replaces.RevokedAt = DateTimeOffset.UtcNow;
            replaces.ReplacedById = entity.Id;
        }

        await _db.SaveChangesAsync(ct);

        return new AuthTokensResponse(access.Token, access.ExpiresAt, rawRefresh);
    }
}
