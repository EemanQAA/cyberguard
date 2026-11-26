using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Wordlist;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CyberGuard.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/wordlist")]
public class WordlistController : ControllerBase
{
    private readonly IWordlistService _service;
    private readonly ICurrentUserService _currentUser;

    public WordlistController(IWordlistService service, ICurrentUserService currentUser)
    {
        _service = service;
        _currentUser = currentUser;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] string? search, CancellationToken ct) =>
        Ok(await _service.ListAsync(_currentUser.UserId, search, ct));

    [HttpPost]
    public async Task<IActionResult> Add(AddWordlistEntryRequest request, CancellationToken ct)
    {
        var result = await _service.AddAsync(_currentUser.UserId, request, ct);
        return StatusCode(StatusCodes.Status201Created, result);
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateWordlistEntryRequest request, CancellationToken ct)
    {
        var result = await _service.UpdateAsync(_currentUser.UserId, id, request, ct);
        return result is null ? NotFound() : Ok(result);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await _service.DeleteAsync(_currentUser.UserId, id, ct) ? NoContent() : NotFound();
}
