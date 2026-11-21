using CyberGuard.Application.Abstractions;
using CyberGuard.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace CyberGuard.Application.Features.Wordlist;

public record AddWordlistEntryRequest(string Word, string? Category);
public record UpdateWordlistEntryRequest(string Word, string? Category);
public record WordlistEntryDto(Guid Id, string Word, string? Category, DateTimeOffset AddedAt);

public interface IWordlistService
{
    Task<WordlistEntryDto> AddAsync(Guid userId, AddWordlistEntryRequest request, CancellationToken ct = default);
    Task<IReadOnlyList<WordlistEntryDto>> ListAsync(Guid userId, string? search, CancellationToken ct = default);
    Task<WordlistEntryDto?> UpdateAsync(Guid userId, Guid id, UpdateWordlistEntryRequest request, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default);

    /// <summary>Used by the client's password engine to fetch the user's own wordlist for local comparison.</summary>
    Task<IReadOnlyList<string>> GetWordsAsync(Guid userId, CancellationToken ct = default);
}

public class WordlistService : IWordlistService
{
    private readonly IApplicationDbContext _db;

    public WordlistService(IApplicationDbContext db) => _db = db;

    public async Task<WordlistEntryDto> AddAsync(Guid userId, AddWordlistEntryRequest request, CancellationToken ct = default)
    {
        var normalized = request.Word.Trim();
        var exists = await _db.WordlistEntries.AnyAsync(
            w => w.UserId == userId && w.Word.ToLower() == normalized.ToLower(), ct);

        if (exists)
        {
            throw new InvalidOperationException("This word is already in your wordlist.");
        }

        var entity = new WordlistEntry
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Word = normalized,
            Category = request.Category,
            AddedAt = DateTimeOffset.UtcNow
        };

        _db.WordlistEntries.Add(entity);
        await _db.SaveChangesAsync(ct);

        return ToDto(entity);
    }

    public async Task<IReadOnlyList<WordlistEntryDto>> ListAsync(Guid userId, string? search, CancellationToken ct = default)
    {
        var query = _db.WordlistEntries.AsNoTracking().Where(w => w.UserId == userId);

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(w => w.Word.Contains(search));
        }

        var items = await query.OrderBy(w => w.Word).ToListAsync(ct);
        return items.Select(ToDto).ToList();
    }

    public async Task<WordlistEntryDto?> UpdateAsync(Guid userId, Guid id, UpdateWordlistEntryRequest request, CancellationToken ct = default)
    {
        var entity = await _db.WordlistEntries.FirstOrDefaultAsync(w => w.UserId == userId && w.Id == id, ct);
        if (entity is null)
        {
            return null;
        }

        entity.Word = request.Word.Trim();
        entity.Category = request.Category;
        await _db.SaveChangesAsync(ct);

        return ToDto(entity);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid id, CancellationToken ct = default)
    {
        var entity = await _db.WordlistEntries.FirstOrDefaultAsync(w => w.UserId == userId && w.Id == id, ct);
        if (entity is null)
        {
            return false;
        }

        _db.WordlistEntries.Remove(entity);
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<IReadOnlyList<string>> GetWordsAsync(Guid userId, CancellationToken ct = default) =>
        await _db.WordlistEntries.AsNoTracking().Where(w => w.UserId == userId).Select(w => w.Word).ToListAsync(ct);

    private static WordlistEntryDto ToDto(WordlistEntry w) => new(w.Id, w.Word, w.Category, w.AddedAt);
}
