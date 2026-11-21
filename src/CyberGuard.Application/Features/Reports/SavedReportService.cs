using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.Reports;

public record BookmarkReportRequest(Guid? PasswordCheckId, Guid? UrlScanId, Guid? PiiScanId, string? Note);
public record UpdateReportNoteRequest(string? Note);
public record SavedReportDto(Guid Id, Guid? PasswordCheckId, Guid? UrlScanId, Guid? PiiScanId, string? Note, DateTimeOffset CreatedAt);

public interface ISavedReportService
{
    Task<SavedReportDto> BookmarkAsync(Guid userId, BookmarkReportRequest request, CancellationToken ct = default);
    Task<IReadOnlyList<SavedReportDto>> ListAsync(Guid userId, string? type, string? search, CancellationToken ct = default);
    Task<SavedReportDto?> UpdateNoteAsync(Guid userId, Guid id, UpdateReportNoteRequest request, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default);
}

public class SavedReportService : ISavedReportService
{
    private readonly IApplicationDbContext _db;

    public SavedReportService(IApplicationDbContext db) => _db = db;

    public async Task<SavedReportDto> BookmarkAsync(Guid userId, BookmarkReportRequest request, CancellationToken ct = default)
    {
        var entity = new SavedReport
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            PasswordCheckId = request.PasswordCheckId,
            UrlScanId = request.UrlScanId,
            PiiScanId = request.PiiScanId,
            Note = request.Note,
            CreatedAt = DateTimeOffset.UtcNow
        };

        if (entity.ReferencedScanCount != 1)
        {
            throw new InvalidOperationException("A report must reference exactly one scan (password check, URL scan or PII scan).");
        }

        _db.SavedReports.Add(entity);
        await _db.SaveChangesAsync(ct);

        return ToDto(entity);
    }

    public async Task<IReadOnlyList<SavedReportDto>> ListAsync(Guid userId, string? type, string? search, CancellationToken ct = default)
    {
        var query = _db.SavedReports.AsNoTracking().Where(r => r.UserId == userId);

        query = type?.ToLowerInvariant() switch
        {
            "password" => query.Where(r => r.PasswordCheckId != null),
            "url" => query.Where(r => r.UrlScanId != null),
            "pii" => query.Where(r => r.PiiScanId != null),
            _ => query
        };

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(r => r.Note != null && r.Note.Contains(search));
        }

        var items = await query.OrderByDescending(r => r.CreatedAt).ToListAsync(ct);
        return items.Select(ToDto).ToList();
    }

    public async Task<SavedReportDto?> UpdateNoteAsync(Guid userId, Guid id, UpdateReportNoteRequest request, CancellationToken ct = default)
    {
        var entity = await _db.SavedReports.FirstOrDefaultAsync(r => r.UserId == userId && r.Id == id, ct);
        if (entity is null) return null;

        entity.Note = request.Note;
        await _db.SaveChangesAsync(ct);
        return ToDto(entity);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.SavedReports.FirstOrDefaultAsync(r => r.UserId == userId && r.Id == id, ct);
        if (entity is null) return false;

        _db.SavedReports.Remove(entity);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private static SavedReportDto ToDto(SavedReport r) =>
        new(r.Id, r.PasswordCheckId, r.UrlScanId, r.PiiScanId, r.Note, r.CreatedAt);
}
