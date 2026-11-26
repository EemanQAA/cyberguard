using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.History;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/history")]
public class HistoryController : ControllerBase
{
    private readonly IHistoryService _service;
    private readonly ICurrentUserService _currentUser;

    public HistoryController(IHistoryService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> Get(
        [FromQuery] string? type, [FromQuery] DateTimeOffset? from, [FromQuery] DateTimeOffset? to,
        [FromQuery] int? risk, CancellationToken ct) =>
        Ok(await _service.GetAsync(_currentUser.UserId, type, from, to, risk, ct));
}
