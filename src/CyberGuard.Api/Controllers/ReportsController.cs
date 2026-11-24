using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Reports;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/reports")]
public class ReportsController : ControllerBase
{
    private readonly ISavedReportService _service;
    private readonly ICurrentUserService _currentUser;

    public ReportsController(ISavedReportService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] string? type, [FromQuery] string? search, CancellationToken ct) =>
        Ok(await _service.ListAsync(_currentUser.UserId, type, search, ct));

    [HttpPost]
    public async Task<IActionResult> Bookmark(BookmarkReportRequest request, CancellationToken ct)
    {
        var result = await _service.BookmarkAsync(_currentUser.UserId, request, ct);
        return StatusCode(StatusCodes.Status201Created, result);
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> UpdateNote(Guid id, UpdateReportNoteRequest request, CancellationToken ct)
    {
        var result = await _service.UpdateNoteAsync(_currentUser.UserId, id, request, ct);
        return result is null ? NotFound() : NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await _service.DeleteAsync(_currentUser.UserId, id, ct) ? NoContent() : NotFound();
}
