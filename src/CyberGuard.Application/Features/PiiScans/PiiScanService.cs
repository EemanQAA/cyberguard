using System.Text.Json;
using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Engines;
using CyberGuard.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.PiiScans;

public record ScanTextRequest(string Text);
public record PiiFindingDto(string Type, string Masked);
public record PiiScanDto(Guid Id, int FindingCount, IReadOnlyList<PiiFindingDto> Findings, DateTimeOffset ScannedAt);

public interface IPiiScanService
{
    Task<PiiScanDto> ScanAsync(Guid userId, ScanTextRequest request, CancellationToken ct = default);
    Task<IReadOnlyList<PiiScanDto>> ListAsync(Guid userId, int page, int pageSize, CancellationToken ct = default);
    Task<PiiScanDto?> GetAsync(Guid userId, Guid id, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default);
}

/// <summary>
/// The raw pasted text lives only in this method's call stack - it is scanned and the
/// local variable falls out of scope at the end of the request. Only masked findings
/// (never the original text) are passed to the database.
/// </summary>
public class PiiScanService : IPiiScanService
{
    private readonly IApplicationDbContext _db;

    public PiiScanService(IApplicationDbContext db) => _db = db;

    public async Task<PiiScanDto> ScanAsync(Guid userId, ScanTextRequest request, CancellationToken ct = default)
    {
        var findings = PiiDetector.Scan(request.Text);

        var entity = new PiiScan
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FindingCount = findings.Count,
            MaskedFindingsJson = JsonSerializer.Serialize(findings),
            ScannedAt = DateTimeOffset.UtcNow
        };

        _db.PiiScans.Add(entity);
        await _db.SaveChangesAsync(ct);

        return ToDto(entity);
    }

    public async Task<IReadOnlyList<PiiScanDto>> ListAsync(Guid userId, int page, int pageSize, CancellationToken ct = default)
    {
        pageSize = Math.Clamp(pageSize, 1, 50);
        page = Math.Max(page, 1);

        var items = await _db.PiiScans.AsNoTracking()
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.ScannedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return items.Select(ToDto).ToList();
    }

    public async Task<PiiScanDto?> GetAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.PiiScans.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == userId && p.Id == id, ct);
        return entity is null ? null : ToDto(entity);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.PiiScans.FirstOrDefaultAsync(p => p.UserId == userId && p.Id == id, ct);
        if (entity is null) return false;

        _db.PiiScans.Remove(entity);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private static PiiScanDto ToDto(PiiScan p)
    {
        var findings = JsonSerializer.Deserialize<List<PiiFindingDto>>(p.MaskedFindingsJson) ?? new List<PiiFindingDto>();
        return new PiiScanDto(p.Id, p.FindingCount, findings, p.ScannedAt);
    }
}
