using System.Net.Http.Json;
using CyberGuard.Application.Abstractions;

namespace CyberGuard.Infrastructure.GeoLocation;

/// <summary>
/// Calls the free ipwho.is API (no key, no billing - Section 3.4). Named HttpClient
/// "ipwhois" is registered with Polly retry/timeout policies in DependencyInjection.cs.
/// </summary>
public class IpWhoIsGeoService : IGeoLocationService
{
    private readonly HttpClient _http;

    public IpWhoIsGeoService(HttpClient http) => _http = http;

    public async Task<GeoLocationResult?> LookupAsync(string ipAddress, CancellationToken ct = default)
    {
        try
        {
            var response = await _http.GetFromJsonAsync<IpWhoIsResponse>($"/{ipAddress}", ct);
            if (response is null || !response.success)
            {
                return null;
            }

            return new GeoLocationResult(
                ipAddress,
                response.country,
                response.city,
                response.latitude,
                response.longitude,
                response.connection?.isp,
                response.connection?.asn?.ToString());
        }
        catch
        {
            // Network failure or free-tier rate limit - the scan should still complete
            // with "location unavailable" rather than fail the whole request.
            return null;
        }
    }

    private record IpWhoIsResponse(
        bool success, string? country, string? city, double? latitude, double? longitude, IpWhoIsConnection? connection);

    private record IpWhoIsConnection(string? isp, int? asn);
}
