using CyberGuard.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.History;

public record HistoryItemDto(string Type, Guid Id, string Summary, int? RiskScore, DateTimeOffset When);

public interface IHistoryService
{
    Task<IReadOnlyList<HistoryItemDto>> GetAsync(
        Guid userId, string? type, DateTimeOffset? from, DateTimeOffset? to, int? minRisk, CancellationToken ct = default);
}

/// <summary>
/// UC-11: one unified, filterable view across the three scan tables, built as a single
/// in-memory merge of three small queries rather than a SQL UNION - simple to read and
/// fast enough at this scale given the per-user indexes on (UserId, *At).
/// </summary>
public class HistoryService : IHistoryService
{
    private readonly IApplicationDbContext _db;

    public HistoryService(IApplicationDbContext db) => _db = db;

    public async Task<IReadOnlyList<HistoryItemDto>> GetAsync(
        Guid userId, string? type, DateTimeOffset? from, DateTimeOffset? to, int? minRisk, CancellationToken ct = default)
    {
        var items = new List<HistoryItemDto>();

        if (type is null || type.Equals("password", StringComparison.OrdinalIgnoreCase))
        {
            var passwordChecks = await _db.PasswordChecks.AsNoTracking()
                .Where(p => p.UserId == userId)
                .Where(p => from == null || p.CheckedAt >= from)
                .Where(p => to == null || p.CheckedAt <= to)
                .ToListAsync(ct);

            items.AddRange(passwordChecks.Select(p =>
                new HistoryItemDto("password", p.Id, $"{p.Rating} ({p.EntropyBits:F0} bits)", null, p.CheckedAt)));
        }

        if (type is null || type.Equals("url", StringComparison.OrdinalIgnoreCase))
        {
            var urlScans = await _db.UrlScans.AsNoTracking()
                .Where(u => u.UserId == userId)
                .Where(u => from == null || u.ScannedAt >= from)
                .Where(u => to == null || u.ScannedAt <= to)
                .Where(u => minRisk == null || u.RiskScore >= minRisk)
                .ToListAsync(ct);

            items.AddRange(urlScans.Select(u => new HistoryItemDto("url", u.Id, u.Url, u.RiskScore, u.ScannedAt)));
        }

        if (type is null || type.Equals("pii", StringComparison.OrdinalIgnoreCase))
        {
            var piiScans = await _db.PiiScans.AsNoTracking()
                .Where(p => p.UserId == userId)
                .Where(p => from == null || p.ScannedAt >= from)
                .Where(p => to == null || p.ScannedAt <= to)
                .ToListAsync(ct);

            items.AddRange(piiScans.Select(p =>
                new HistoryItemDto("pii", p.Id, $"{p.FindingCount} finding(s)", null, p.ScannedAt)));
        }

        return items.OrderByDescending(i => i.When).ToList();
    }
}
