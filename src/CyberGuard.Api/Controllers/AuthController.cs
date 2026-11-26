using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _auth;

    public AuthController(IAuthService auth) => _auth = auth;

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        var result = await _auth.RegisterAsync(request, ct);
        if (!result.Succeeded)
        {
            return Problem(detail: string.Join(" ", result.Errors), statusCode: StatusCodes.Status400BadRequest);
        }

        return StatusCode(StatusCodes.Status201Created, result.Value);
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var result = await _auth.LoginAsync(request, ct);
        if (!result.Succeeded)
        {
            return Problem(detail: string.Join(" ", result.Errors), statusCode: StatusCodes.Status401Unauthorized);
        }

        SetRefreshTokenCookie(result.Value!.RefreshToken);
        return Ok(new { accessToken = result.Value.AccessToken, accessTokenExpiresAt = result.Value.AccessTokenExpiresAt });
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        if (!Request.Cookies.TryGetValue("cg_refresh", out var refreshToken) || string.IsNullOrEmpty(refreshToken))
        {
            return Problem(detail: "No refresh token cookie present.", statusCode: StatusCodes.Status401Unauthorized);
        }

        var result = await _auth.RefreshAsync(refreshToken, ct);
        if (!result.Succeeded)
        {
            Response.Cookies.Delete("cg_refresh");
            return Problem(detail: string.Join(" ", result.Errors), statusCode: StatusCodes.Status401Unauthorized);
        }

        SetRefreshTokenCookie(result.Value!.RefreshToken);
        return Ok(new { accessToken = result.Value.AccessToken, accessTokenExpiresAt = result.Value.AccessTokenExpiresAt });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        if (Request.Cookies.TryGetValue("cg_refresh", out var refreshToken) && !string.IsNullOrEmpty(refreshToken))
        {
            await _auth.LogoutAsync(refreshToken, ct);
        }

        Response.Cookies.Delete("cg_refresh");
        return NoContent();
    }

    private void SetRefreshTokenCookie(string rawToken)
    {
        Response.Cookies.Append("cg_refresh", rawToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/v1/auth",
            Expires = DateTimeOffset.UtcNow.AddDays(7)
        });
    }
}
