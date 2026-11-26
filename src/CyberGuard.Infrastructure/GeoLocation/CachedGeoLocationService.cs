using CyberGuard.Application.Abstractions;
using Microsoft.Extensions.Caching.Memory;

namespace CyberGuard.Infrastructure.GeoLocation;

/// <summary>
/// Decorator: wraps IpWhoIsGeoService behind the same IGeoLocationService interface,
/// adding an in-memory cache (24h on success, 10min negative cache on failure - Table 12).
/// Swap IMemoryCache for IDistributedCache (Redis) here alone if the API ever scales out.
/// </summary>
public class CachedGeoLocationService : IGeoLocationService
{
    private readonly IGeoLocationService _inner;
    private readonly IMemoryCache _cache;

    public CachedGeoLocationService(IGeoLocationService inner, IMemoryCache cache)
    {
        _inner = inner;
        _cache = cache;
    }

    public async Task<GeoLocationResult?> LookupAsync(string ipAddress, CancellationToken ct = default)
    {
        var cacheKey = $"geo:{ipAddress}";
        if (_cache.TryGetValue(cacheKey, out GeoLocationResult? cached))
        {
            return cached;
        }

        var result = await _inner.LookupAsync(ipAddress, ct);
        var ttl = result is not null ? TimeSpan.FromHours(24) : TimeSpan.FromMinutes(10);
        _cache.Set(cacheKey, result, ttl);

        return result;
    }
}
