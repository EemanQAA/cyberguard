using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Dashboard;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/dashboard")]
public class DashboardController : ControllerBase
{
    private readonly IDashboardService _service;
    private readonly ICurrentUserService _currentUser;

    public DashboardController(IDashboardService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken ct) => Ok(await _service.GetAsync(_currentUser.UserId, ct));
}
