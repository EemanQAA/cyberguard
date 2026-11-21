using System.Net;
using System.Text.Json;
using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Engines;
using CyberGuard.Domain.Entities;
using CyberGuard.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.UrlScans;

public record ScanUrlRequest(string Url);

public record UrlScanDto(
    Guid Id, string Url, int RiskScore, string RiskLabel, IReadOnlyList<string> Reasons,
    UrlVerdict Verdict, string? Country, string? City, double? Latitude, double? Longitude,
    DateTimeOffset ScannedAt);

public interface IUrlScanService
{
    Task<UrlScanDto> ScanAsync(Guid userId, ScanUrlRequest request, CancellationToken ct = default);
    Task<IReadOnlyList<UrlScanDto>> ListAsync(Guid userId, int page, int pageSize, CancellationToken ct = default);
    Task<UrlScanDto?> GetAsync(Guid userId, Guid id, CancellationToken ct = default);
    Task<bool> SetVerdictAsync(Guid userId, Guid id, UrlVerdict verdict, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default);
}

/// <summary>
/// Combines the static heuristic engine (Domain) with an optional geolocation lookup.
/// ML scoring (OnnxPhishingModel / hybrid score) plugs in here in Sprint 3+ without
/// changing the controller or the DTO shape.
/// </summary>
public class UrlScanService : IUrlScanService
{
    private readonly IApplicationDbContext _db;
    private readonly IGeoLocationService _geo;

    public UrlScanService(IApplicationDbContext db, IGeoLocationService geo)
    {
        _db = db;
        _geo = geo;
    }

    public async Task<UrlScanDto> ScanAsync(Guid userId, ScanUrlRequest request, CancellationToken ct = default)
    {
        var risk = UrlRiskEngine.Evaluate(request.Url);

        var modelVersion = await _db.ModelVersions.FirstOrDefaultAsync(m => m.IsActive, ct)
            ?? await SeedRulesOnlyModelVersionAsync(ct);

        GeoLocationResult? geo = null;
        Guid? geoId = null;
        if (Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
        {
            var ip = await TryResolveAsync(uri.Host, ct);
            if (ip is not null)
            {
                geo = await _geo.LookupAsync(ip, ct);
                if (geo is not null)
                {
                    var existing = await _db.IpGeolocations.FirstOrDefaultAsync(g => g.Ip == ip, ct);
                    if (existing is null)
                    {
                        existing = new IpGeolocation
                        {
                            Id = Guid.NewGuid(),
                            Ip = ip,
                            Country = geo.Country,
                            City = geo.City,
                            Latitude = geo.Latitude,
                            Longitude = geo.Longitude,
                            Isp = geo.Isp,
                            Asn = geo.Asn,
                            CachedAt = DateTimeOffset.UtcNow
                        };
                        _db.IpGeolocations.Add(existing);
                    }

                    geoId = existing.Id;
                }
            }
        }

        var entity = new UrlScan
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Url = request.Url,
            RiskScore = risk.Score,
            ReasonsJson = JsonSerializer.Serialize(risk.Reasons.Select(r => r.Message)),
            Verdict = UrlVerdict.Unknown,
            ModelVersionId = modelVersion.Id,
            IpGeolocationId = geoId,
            ScannedAt = DateTimeOffset.UtcNow
        };

        _db.UrlScans.Add(entity);
        await _db.SaveChangesAsync(ct);

        return ToDto(entity, risk.Label, geo);
    }

    public async Task<IReadOnlyList<UrlScanDto>> ListAsync(Guid userId, int page, int pageSize, CancellationToken ct = default)
    {
        pageSize = Math.Clamp(pageSize, 1, 50);
        page = Math.Max(page, 1);

        var items = await _db.UrlScans.AsNoTracking()
            .Where(u => u.UserId == userId)
            .OrderByDescending(u => u.ScannedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return items.Select(i => ToDto(i, LabelFor(i.RiskScore), null)).ToList();
    }

    public async Task<UrlScanDto?> GetAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.UrlScans.AsNoTracking().FirstOrDefaultAsync(u => u.UserId == userId && u.Id == id, ct);
        if (entity is null) return null;

        GeoLocationResult? geo = null;
        if (entity.IpGeolocationId is not null)
        {
            var cached = await _db.IpGeolocations.AsNoTracking().FirstOrDefaultAsync(g => g.Id == entity.IpGeolocationId, ct);
            if (cached is not null)
            {
                geo = new GeoLocationResult(cached.Ip, cached.Country, cached.City, cached.Latitude, cached.Longitude, cached.Isp, cached.Asn);
            }
        }

        return ToDto(entity, LabelFor(entity.RiskScore), geo);
    }

    public async Task<bool> SetVerdictAsync(Guid userId, Guid id, UrlVerdict verdict, CancellationToken ct = default)
    {
        var entity = await _db.UrlScans.FirstOrDefaultAsync(u => u.UserId == userId && u.Id == id, ct);
        if (entity is null) return false;

        entity.SetVerdict(verdict);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.UrlScans.FirstOrDefaultAsync(u => u.UserId == userId && u.Id == id, ct);
        if (entity is null) return false;

        _db.UrlScans.Remove(entity);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private async Task<ModelVersion> SeedRulesOnlyModelVersionAsync(CancellationToken ct)
    {
        var seeded = new ModelVersion { Id = Guid.NewGuid(), Version = "rules-v1", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        _db.ModelVersions.Add(seeded);
        await _db.SaveChangesAsync(ct);
        return seeded;
    }

    private static async Task<string?> TryResolveAsync(string host, CancellationToken ct)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, ct);
            return addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString();
        }
        catch
        {
            return null; // DNS failure should not break the scan - it just returns without a location
        }
    }

    private static string LabelFor(int score) => score switch { >= 70 => "High", >= 40 => "Medium", _ => "Low" };

    private static UrlScanDto ToDto(UrlScan u, string label, GeoLocationResult? geo)
    {
        var reasons = JsonSerializer.Deserialize<List<string>>(u.ReasonsJson) ?? new List<string>();
        return new UrlScanDto(u.Id, u.Url, u.RiskScore, label, reasons, u.Verdict,
            geo?.Country, geo?.City, geo?.Latitude, geo?.Longitude, u.ScannedAt);
    }
}
