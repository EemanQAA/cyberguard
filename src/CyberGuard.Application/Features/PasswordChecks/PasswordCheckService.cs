using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Entities;
using CyberGuard.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.PasswordChecks;

public record SavePasswordCheckRequest(double EntropyBits, PasswordRating Rating, bool MatchedCommonOrWordlist);

public record PasswordCheckDto(Guid Id, double EntropyBits, PasswordRating Rating, bool MatchedCommonOrWordlist, DateTimeOffset CheckedAt);

public interface IPasswordCheckService
{
    Task<PasswordCheckDto> SaveAsync(Guid userId, SavePasswordCheckRequest request, CancellationToken ct = default);
    Task<IReadOnlyList<PasswordCheckDto>> ListAsync(Guid userId, int page, int pageSize, CancellationToken ct = default);
    Task<PasswordCheckDto?> GetAsync(Guid userId, Guid id, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default);
}

public class PasswordCheckService : IPasswordCheckService
{
    private readonly IApplicationDbContext _db;

    public PasswordCheckService(IApplicationDbContext db) => _db = db;

    public async Task<PasswordCheckDto> SaveAsync(Guid userId, SavePasswordCheckRequest request, CancellationToken ct = default)
    {
        var entity = new PasswordCheck
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            EntropyBits = request.EntropyBits,
            Rating = request.Rating,
            MatchedCommonOrWordlist = request.MatchedCommonOrWordlist,
            CheckedAt = DateTimeOffset.UtcNow
        };

        _db.PasswordChecks.Add(entity);
        await _db.SaveChangesAsync(ct);

        return ToDto(entity);
    }

    public async Task<IReadOnlyList<PasswordCheckDto>> ListAsync(Guid userId, int page, int pageSize, CancellationToken ct = default)
    {
        pageSize = Math.Clamp(pageSize, 1, 50);
        page = Math.Max(page, 1);

        var items = await _db.PasswordChecks
            .AsNoTracking()
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.CheckedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return items.Select(ToDto).ToList();
    }

    public async Task<PasswordCheckDto?> GetAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.PasswordChecks
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.UserId == userId && p.Id == id, ct);

        return entity is null ? null : ToDto(entity);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.PasswordChecks.FirstOrDefaultAsync(p => p.UserId == userId && p.Id == id, ct);
        if (entity is null)
        {
            return false;
        }

        _db.PasswordChecks.Remove(entity);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private static PasswordCheckDto ToDto(PasswordCheck p) =>
        new(p.Id, p.EntropyBits, p.Rating, p.MatchedCommonOrWordlist, p.CheckedAt);
}
