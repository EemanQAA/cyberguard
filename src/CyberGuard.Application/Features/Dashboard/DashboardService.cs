using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.Dashboard;

public record DashboardDto(
    double? Score, string Label, int PasswordsChecked, int UrlsScanned, int OpenAlerts, int ItemsToFix);

/// <summary>
/// Calculates the 0-100 hygiene score on demand from already-stored summaries
/// (Section 3.2 / Table 2) - no extra table is needed. A component with no data yet
/// is skipped and the remaining weights are rescaled.
/// </summary>
public interface IDashboardService
{
    Task<DashboardDto> GetAsync(Guid userId, CancellationToken ct = default);
}

public class DashboardService : IDashboardService
{
    private readonly IApplicationDbContext _db;

    public DashboardService(IApplicationDbContext db) => _db = db;

    public async Task<DashboardDto> GetAsync(Guid userId, CancellationToken ct = default)
    {
        var recentPasswordRatings = await _db.PasswordChecks.AsNoTracking()
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.CheckedAt)
            .Take(10)
            .Select(p => p.Rating)
            .ToListAsync(ct);

        var recentUrlRiskScores = await _db.UrlScans.AsNoTracking()
            .Where(u => u.UserId == userId)
            .OrderByDescending(u => u.ScannedAt)
            .Take(10)
            .Select(u => u.RiskScore)
            .ToListAsync(ct);

        var openHighAlerts = await _db.Alerts.AsNoTracking()
            .CountAsync(a => a.UserId == userId && a.Status != AlertStatus.Reviewed && a.Severity == AlertSeverity.High, ct);

        var openMediumAlerts = await _db.Alerts.AsNoTracking()
            .CountAsync(a => a.UserId == userId && a.Status != AlertStatus.Reviewed && a.Severity == AlertSeverity.Medium, ct);

        var totalPasswordChecks = await _db.PasswordChecks.AsNoTracking().CountAsync(p => p.UserId == userId, ct);
        var totalUrlScans = await _db.UrlScans.AsNoTracking().CountAsync(u => u.UserId == userId, ct);
        var openAlerts = await _db.Alerts.AsNoTracking().CountAsync(a => a.UserId == userId && a.Status != AlertStatus.Reviewed, ct);

        double weightedSum = 0;
        double totalWeight = 0;

        if (recentPasswordRatings.Count > 0)
        {
            var avg = recentPasswordRatings.Average(r => r switch
            {
                PasswordRating.Strong => 100,
                PasswordRating.Fair => 60,
                _ => 20
            });
            weightedSum += avg * 0.40;
            totalWeight += 0.40;
        }

        if (recentUrlRiskScores.Count > 0)
        {
            var avg = recentUrlRiskScores.Average(s => 100 - s);
            weightedSum += avg * 0.30;
            totalWeight += 0.30;
        }

        // Data leaks component always has a value (starts at 100, even with zero alerts).
        var dataLeaksScore = Math.Max(0, 100 - 25 * openHighAlerts - 10 * openMediumAlerts);
        weightedSum += dataLeaksScore * 0.30;
        totalWeight += 0.30;

        double? score = totalWeight > 0 ? weightedSum / totalWeight : null;

        var label = score switch
        {
            null => "No score yet",
            >= 80 => "Excellent",
            >= 60 => "Good",
            >= 40 => "Fair",
            _ => "At risk"
        };

        return new DashboardDto(score, label, totalPasswordChecks, totalUrlScans, openAlerts, openAlerts);
    }
}
