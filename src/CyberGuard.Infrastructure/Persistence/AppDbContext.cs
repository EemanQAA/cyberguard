using Microsoft.AspNetCore.Identity;
using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Entities;
using CyberGuard.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Infrastructure.Persistence;

public class AppDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>, IApplicationDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<PasswordCheck> PasswordChecks => Set<PasswordCheck>();
    public DbSet<UrlScan> UrlScans => Set<UrlScan>();
    public DbSet<PiiScan> PiiScans => Set<PiiScan>();
    public DbSet<SavedReport> SavedReports => Set<SavedReport>();
    public DbSet<WordlistEntry> WordlistEntries => Set<WordlistEntry>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<IpGeolocation> IpGeolocations => Set<IpGeolocation>();
    public DbSet<ModelVersion> ModelVersions => Set<ModelVersion>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);
    }
}
