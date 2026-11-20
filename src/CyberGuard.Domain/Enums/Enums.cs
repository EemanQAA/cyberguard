namespace CyberGuard.Domain.Enums;

public enum PasswordRating
{
    Weak,
    Fair,
    Strong
}

public enum UrlVerdict
{
    Unknown,
    Safe,
    Phishing
}

public enum AlertSeverity
{
    Low,
    Medium,
    High
}

public enum AlertStatus
{
    New,
    Read,
    Reviewed
}

public enum ScanSourceType
{
    PasswordCheck,
    UrlScan,
    PiiScan
}
