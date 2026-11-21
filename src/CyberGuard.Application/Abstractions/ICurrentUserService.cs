namespace CyberGuard.Application.Abstractions;

/// <summary>
/// Resolves the calling user's id from the validated JWT. Implemented in the Api layer
/// (reads HttpContext.User) and injected into Application services, so every
/// repository/service method can enforce per-user authorisation (Section 5 design decision).
/// </summary>
public interface ICurrentUserService
{
    Guid UserId { get; }
}
