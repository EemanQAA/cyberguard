using Microsoft.AspNetCore.Identity;

namespace CyberGuard.Infrastructure.Identity;

/// <summary>
/// ASP.NET Core Identity user. Kept in Infrastructure (it depends on the Identity
/// framework) - everything else in the app only ever needs the plain Guid UserId.
/// </summary>
public class ApplicationUser : IdentityUser<Guid>
{
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
