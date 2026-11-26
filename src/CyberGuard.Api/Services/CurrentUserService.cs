using System.Security.Claims;
using CyberGuard.Application.Abstractions;

namespace CyberGuard.Api.Services;

public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUserService(IHttpContextAccessor httpContextAccessor) => _httpContextAccessor = httpContextAccessor;

    public Guid UserId
    {
        get
        {
            var raw = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? _httpContextAccessor.HttpContext?.User.FindFirstValue("sub");

            if (raw is null || !Guid.TryParse(raw, out var id))
            {
                throw new UnauthorizedAccessException("No authenticated user on this request.");
            }

            return id;
        }
    }
}
