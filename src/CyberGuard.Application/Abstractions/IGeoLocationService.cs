namespace CyberGuard.Application.Abstractions;

public record GeoLocationResult(string Ip, string? Country, string? City, double? Latitude, double? Longitude, string? Isp, string? Asn);

/// <summary>
/// Port for the free ipwho.is geolocation lookup (Section 3.4 / Table 12). Implemented in
/// Infrastructure as CachedGeoLocationService wrapping IpWhoIsGeoService (decorator pattern),
/// so callers never know whether a result came from cache or the network.
/// </summary>
public interface IGeoLocationService
{
    Task<GeoLocationResult?> LookupAsync(string ipAddress, CancellationToken ct = default);
}
