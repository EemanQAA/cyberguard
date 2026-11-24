using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.UrlScans;
using CyberGuard.Domain.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

public record SetVerdictRequest(UrlVerdict Verdict);

[ApiController]
[Authorize]
[Route("api/v1/url-scans")]
public class UrlScansController : ControllerBase
{
    private readonly IUrlScanService _service;
    private readonly ICurrentUserService _currentUser;

    public UrlScansController(IUrlScanService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default) =>
        Ok(await _service.ListAsync(_currentUser.UserId, page, pageSize, ct));

    [HttpPost]
    public async Task<IActionResult> Scan(ScanUrlRequest request, CancellationToken ct)
    {
        var result = await _service.ScanAsync(_currentUser.UserId, request, ct);
        return StatusCode(StatusCodes.Status201Created, result);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var result = await _service.GetAsync(_currentUser.UserId, id, ct);
        return result is null ? NotFound() : Ok(result);
    }

    [HttpPatch("{id:guid}/verdict")]
    public async Task<IActionResult> SetVerdict(Guid id, SetVerdictRequest request, CancellationToken ct) =>
        await _service.SetVerdictAsync(_currentUser.UserId, id, request.Verdict, ct) ? NoContent() : NotFound();

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await _service.DeleteAsync(_currentUser.UserId, id, ct) ? NoContent() : NotFound();
}
