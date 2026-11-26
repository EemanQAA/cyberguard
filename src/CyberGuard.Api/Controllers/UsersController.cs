using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/users")]
public class UsersController : ControllerBase
{
    private readonly IAuthService _auth;
    private readonly ICurrentUserService _currentUser;

    public UsersController(IAuthService auth, ICurrentUserService currentUser)
    {
        _auth = auth;
        _currentUser = currentUser;
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetMe(CancellationToken ct)
    {
        var profile = await _auth.GetProfileAsync(_currentUser.UserId, ct);
        return profile is null ? NotFound() : Ok(profile);
    }

    [HttpPut("me")]
    public async Task<IActionResult> UpdateMe(UpdateProfileRequest request, CancellationToken ct)
    {
        var result = await _auth.UpdateProfileAsync(_currentUser.UserId, request, ct);
        if (!result.Succeeded)
        {
            return Problem(detail: string.Join(" ", result.Errors), statusCode: StatusCodes.Status400BadRequest);
        }

        return Ok(result.Value);
    }

    [HttpDelete("me")]
    public async Task<IActionResult> DeleteMe(CancellationToken ct)
    {
        await _auth.DeleteAccountAsync(_currentUser.UserId, ct);
        return NoContent();
    }
}
