using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Entities;
using CyberGuard.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.Alerts;

public record AlertDto(Guid Id, AlertSeverity Severity, string Message, AlertStatus Status, DateTimeOffset CreatedAt);

public interface IAlertService
{
    /// <summary>Called by the scan services when a result is high/medium risk (UC-09 auto-flagging).</summary>
    Task RaiseAsync(Guid userId, AlertSeverity severity, string message, ScanSourceType? sourceType, Guid? sourceId, CancellationToken ct = default);

    Task<IReadOnlyList<AlertDto>> ListAsync(Guid userId, AlertStatus? status, CancellationToken ct = default);
    Task<bool> SetStatusAsync(Guid userId, Guid id, AlertStatus status, CancellationToken ct = default);
    Task MarkAllReadAsync(Guid userId, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default);
    Task<int> CountOpenAsync(Guid userId, CancellationToken ct = default);
}

public class AlertService : IAlertService
{
    private readonly IApplicationDbContext _db;

    public AlertService(IApplicationDbContext db) => _db = db;

    public async Task RaiseAsync(Guid userId, AlertSeverity severity, string message, ScanSourceType? sourceType, Guid? sourceId, CancellationToken ct = default)
    {
        _db.Alerts.Add(new Alert
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Severity = severity,
            Message = message,
            SourceType = sourceType,
            SourceId = sourceId,
            Status = AlertStatus.New,
            CreatedAt = DateTimeOffset.UtcNow
        });

        await _db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AlertDto>> ListAsync(Guid userId, AlertStatus? status, CancellationToken ct = default)
    {
        var query = _db.Alerts.AsNoTracking().Where(a => a.UserId == userId);
        if (status is not null)
        {
            query = query.Where(a => a.Status == status);
        }

        var items = await query.OrderByDescending(a => a.CreatedAt).ToListAsync(ct);
        return items.Select(ToDto).ToList();
    }

    public async Task<bool> SetStatusAsync(Guid userId, Guid id, AlertStatus status, CancellationToken ct = default)
    {
        var entity = await _db.Alerts.FirstOrDefaultAsync(a => a.UserId == userId && a.Id == id, ct);
        if (entity is null) return false;

        if (status == AlertStatus.Reviewed) entity.MarkReviewed();
        else if (status == AlertStatus.Read) entity.MarkRead();
        else entity.Status = status;

        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task MarkAllReadAsync(Guid userId, CancellationToken ct = default)
    {
        var news = await _db.Alerts.Where(a => a.UserId == userId && a.Status == AlertStatus.New).ToListAsync(ct);
        foreach (var a in news) a.MarkRead();
        await _db.SaveChangesAsync(ct);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.Alerts.FirstOrDefaultAsync(a => a.UserId == userId && a.Id == id, ct);
        if (entity is null) return false;

        _db.Alerts.Remove(entity);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<int> CountOpenAsync(Guid userId, CancellationToken ct = default) =>
        await _db.Alerts.AsNoTracking().CountAsync(a => a.UserId == userId && a.Status != AlertStatus.Reviewed, ct);

    private static AlertDto ToDto(Alert a) => new(a.Id, a.Severity, a.Message, a.Status, a.CreatedAt);
}
