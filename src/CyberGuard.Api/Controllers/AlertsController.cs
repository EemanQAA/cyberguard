using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Alerts;
using CyberGuard.Domain.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

public record SetAlertStatusRequest(AlertStatus Status);

[ApiController]
[Authorize]
[Route("api/v1/alerts")]
public class AlertsController : ControllerBase
{
    private readonly IAlertService _service;
    private readonly ICurrentUserService _currentUser;

    public AlertsController(IAlertService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] AlertStatus? status, CancellationToken ct) =>
        Ok(await _service.ListAsync(_currentUser.UserId, status, ct));

    [HttpPatch("{id:guid}/status")]
    public async Task<IActionResult> SetStatus(Guid id, SetAlertStatusRequest request, CancellationToken ct) =>
        await _service.SetStatusAsync(_currentUser.UserId, id, request.Status, ct) ? NoContent() : NotFound();

    [HttpPost("mark-all-read")]
    public async Task<IActionResult> MarkAllRead(CancellationToken ct)
    {
        await _service.MarkAllReadAsync(_currentUser.UserId, ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await _service.DeleteAsync(_currentUser.UserId, id, ct) ? NoContent() : NotFound();
}
