using CyberGuard.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Abstractions;

/// <summary>
/// The Application layer's view of the database - just the DbSets it needs, with no
/// reference to EF Core's provider or to Identity. Implemented by
/// CyberGuard.Infrastructure.Persistence.AppDbContext.
/// </summary>
public interface IApplicationDbContext
{
    DbSet<PasswordCheck> PasswordChecks { get; }
    DbSet<UrlScan> UrlScans { get; }
    DbSet<PiiScan> PiiScans { get; }
    DbSet<SavedReport> SavedReports { get; }
    DbSet<WordlistEntry> WordlistEntries { get; }
    DbSet<Alert> Alerts { get; }
    DbSet<IpGeolocation> IpGeolocations { get; }
    DbSet<ModelVersion> ModelVersions { get; }
    DbSet<RefreshToken> RefreshTokens { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
