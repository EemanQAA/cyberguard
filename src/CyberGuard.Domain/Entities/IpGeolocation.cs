namespace CyberGuard.Domain.Entities;

/// <summary>
/// One cached location per IP address, reused across users' URL scans (Table 9 / Table 12).
/// </summary>
public class IpGeolocation
{
    public Guid Id { get; set; }
    public string Ip { get; set; } = default!;
    public string? Country { get; set; }
    public string? City { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string? Isp { get; set; }
    public string? Asn { get; set; }
    public DateTimeOffset CachedAt { get; set; } = DateTimeOffset.UtcNow;
}
