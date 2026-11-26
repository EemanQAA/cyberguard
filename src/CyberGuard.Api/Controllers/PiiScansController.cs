using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.PiiScans;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/pii-scans")]
public class PiiScansController : ControllerBase
{
    private readonly IPiiScanService _service;
    private readonly ICurrentUserService _currentUser;

    public PiiScansController(IPiiScanService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default) =>
        Ok(await _service.ListAsync(_currentUser.UserId, page, pageSize, ct));

    [HttpPost]
    public async Task<IActionResult> Scan(ScanTextRequest request, CancellationToken ct)
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

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await _service.DeleteAsync(_currentUser.UserId, id, ct) ? NoContent() : NotFound();
}
