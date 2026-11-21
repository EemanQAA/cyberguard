namespace CyberGuard.Application.Features.Auth;

public record RegisterRequest(string Email, string Password);

public record LoginRequest(string Email, string Password);

public record AuthTokensResponse(string AccessToken, DateTimeOffset AccessTokenExpiresAt, string RefreshToken);

public record UserProfileDto(Guid Id, string Email, DateTimeOffset CreatedAt);

public record UpdateProfileRequest(string? Email);

/// <summary>
/// Simple success/failure wrapper so the Api layer can map to the right HTTP status
/// without the Application layer throwing exceptions for expected failures
/// (e.g. "email already registered", "invalid credentials").
/// </summary>
public class AuthResult<T>
{
    public bool Succeeded { get; }
    public T? Value { get; }
    public IReadOnlyList<string> Errors { get; }

    private AuthResult(bool succeeded, T? value, IReadOnlyList<string> errors)
    {
        Succeeded = succeeded;
        Value = value;
        Errors = errors;
    }

    public static AuthResult<T> Success(T value) => new(true, value, Array.Empty<string>());

    public static AuthResult<T> Failure(params string[] errors) => new(false, default, errors);
}
