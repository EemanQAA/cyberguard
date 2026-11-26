using CyberGuard.Application.Abstractions;
using CyberGuard.Application.Features.Alerts;
using CyberGuard.Application.Features.Dashboard;
using CyberGuard.Application.Features.History;
using CyberGuard.Application.Features.PasswordChecks;
using CyberGuard.Application.Features.PiiScans;
using CyberGuard.Application.Features.Reports;
using CyberGuard.Application.Features.UrlScans;
using CyberGuard.Application.Features.Wordlist;
using CyberGuard.Infrastructure.GeoLocation;
using CyberGuard.Infrastructure.Identity;
using CyberGuard.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Polly;
using Polly.Extensions.Http;

namespace CyberGuard.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Default")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Default. Set it via appsettings, an environment variable, or dotnet user-secrets.");

        services.AddDbContext<AppDbContext>(options => options.UseNpgsql(connectionString));

        services.AddScoped<IApplicationDbContext>(sp => sp.GetRequiredService<AppDbContext>());

        services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.Password.RequiredLength = 8;
                options.User.RequireUniqueEmail = true;
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
        services.AddSingleton<IJwtTokenService, JwtTokenService>();
        services.AddScoped<IAuthService, AuthService>();

        services.AddMemoryCache();

        services.AddHttpClient<IpWhoIsGeoService>(client =>
            {
                client.BaseAddress = new Uri("https://ipwho.is");
                client.Timeout = TimeSpan.FromSeconds(4);
            })
            .AddPolicyHandler(GetRetryPolicy())
            .AddPolicyHandler(GetTimeoutPolicy());

        services.AddScoped<IGeoLocationService>(sp =>
            new CachedGeoLocationService(
                sp.GetRequiredService<IpWhoIsGeoService>(),
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>()));

        services.AddScoped<IPasswordCheckService, PasswordCheckService>();
        services.AddScoped<IUrlScanService, UrlScanService>();
        services.AddScoped<IPiiScanService, PiiScanService>();
        services.AddScoped<ISavedReportService, SavedReportService>();
        services.AddScoped<IWordlistService, WordlistService>();
        services.AddScoped<IAlertService, AlertService>();
        services.AddScoped<IDashboardService, DashboardService>();
        services.AddScoped<IHistoryService, HistoryService>();

        return services;
    }

    private static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy() =>
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .WaitAndRetryAsync(2, attempt => TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt)));

    private static IAsyncPolicy<HttpResponseMessage> GetTimeoutPolicy() =>
        Policy.TimeoutAsync<HttpResponseMessage>(TimeSpan.FromSeconds(3));
}
