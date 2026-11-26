using CyberGuard.Domain.Entities;
using CyberGuard.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CyberGuard.Infrastructure.Persistence.Configurations;

// Every user-owned table: UUID PK, FK to AspNetUsers with ON DELETE CASCADE so that
// deleting an account cascades everywhere in one operation (Table 9 / UC-03).

public class PasswordCheckConfiguration : IEntityTypeConfiguration<PasswordCheck>
{
    public void Configure(EntityTypeBuilder<PasswordCheck> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.HasIndex(x => new { x.UserId, x.CheckedAt });
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class UrlScanConfiguration : IEntityTypeConfiguration<UrlScan>
{
    public void Configure(EntityTypeBuilder<UrlScan> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Url).HasMaxLength(2048).IsRequired();
        b.HasIndex(x => new { x.UserId, x.ScannedAt });
        b.ToTable(t => t.HasCheckConstraint("CK_UrlScans_RiskScore", "\"RiskScore\" BETWEEN 0 AND 100"));
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<ModelVersion>().WithMany().HasForeignKey(x => x.ModelVersionId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<IpGeolocation>().WithMany().HasForeignKey(x => x.IpGeolocationId).OnDelete(DeleteBehavior.SetNull);
    }
}

public class PiiScanConfiguration : IEntityTypeConfiguration<PiiScan>
{
    public void Configure(EntityTypeBuilder<PiiScan> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.HasIndex(x => new { x.UserId, x.ScannedAt });
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class SavedReportConfiguration : IEntityTypeConfiguration<SavedReport>
{
    public void Configure(EntityTypeBuilder<SavedReport> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.ToTable(t => t.HasCheckConstraint(
            "CK_SavedReports_ExactlyOneScan",
            "num_nonnulls(\"PasswordCheckId\", \"UrlScanId\", \"PiiScanId\") = 1"));
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<PasswordCheck>().WithMany().HasForeignKey(x => x.PasswordCheckId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<UrlScan>().WithMany().HasForeignKey(x => x.UrlScanId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<PiiScan>().WithMany().HasForeignKey(x => x.PiiScanId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class WordlistEntryConfiguration : IEntityTypeConfiguration<WordlistEntry>
{
    public void Configure(EntityTypeBuilder<WordlistEntry> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Word).HasMaxLength(100).IsRequired();
        b.HasIndex(x => new { x.UserId, x.Word }).IsUnique();
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class AlertConfiguration : IEntityTypeConfiguration<Alert>
{
    public void Configure(EntityTypeBuilder<Alert> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Message).HasMaxLength(500).IsRequired();
        b.HasIndex(x => new { x.UserId, x.Status });
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
        b.HasIndex(x => x.TokenHash).IsUnique();
        b.HasIndex(x => x.FamilyId);
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class IpGeolocationConfiguration : IEntityTypeConfiguration<IpGeolocation>
{
    public void Configure(EntityTypeBuilder<IpGeolocation> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Ip).HasMaxLength(64).IsRequired();
        b.HasIndex(x => x.Ip).IsUnique();
    }
}

public class ModelVersionConfiguration : IEntityTypeConfiguration<ModelVersion>
{
    public void Configure(EntityTypeBuilder<ModelVersion> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasDefaultValueSql("gen_random_uuid()");
        b.Property(x => x.Version).HasMaxLength(50).IsRequired();
        b.HasIndex(x => x.IsActive).HasFilter("\"IsActive\" = true").IsUnique();
    }
}
