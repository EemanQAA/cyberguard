namespace CyberGuard.Domain.Entities;

/// <summary>
/// Tracks which phishing scoring model produced a given UrlScan. In Sprint 1 there is
/// a single seeded "rules-v1" row (heuristics only); the ML model (Sprint 3+) adds further
/// rows via the training pipeline (see design doc Section 9/UC-13).
/// </summary>
public class ModelVersion
{
    public Guid Id { get; set; }
    public string Version { get; set; } = "rules-v1";
    public bool IsActive { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
