namespace MatchmakingService.Configuration;

public sealed class MatchmakingOptions
{
    public const string SectionName = "Matchmaking";
    public TimeSpan SessionExpirationTimeout { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromSeconds(5);
    public int MaxActiveSessions { get; set; } = 1000;
    public int MaxSessionsPerIp { get; set; } = 10;
    public int MaxRequestBodyBytes { get; set; } = 16 * 1024;
    public int MaxRequestHeadersTotalSize { get; set; } = 8 * 1024;
    public int MaxAuthorizationHeaderBytes { get; set; } = 1024;
    public int MaxConcurrentConnections { get; set; } = 256;
    public string DatabasePath { get; set; } = "data/matchmaking.db";
    public TokenOptions Tokens { get; set; } = new();
    public LoginProtectionOptions LoginProtection { get; set; } = new();
    public RateLimitOptions RateLimits { get; set; } = new();
}

public sealed class TokenOptions
{
    public string Issuer { get; set; } = "matchmaking-service";
    public string ApiAudience { get; set; } = "matchmaking-api";
    // Each key may be supplied as a PEM file path or as inline PEM text (inline wins). Never commit either.
    public string? AuthSigningKeyPath { get; set; }
    public string? AuthSigningKeyPem { get; set; }
    public string? NatSigningKeyPath { get; set; }
    public string? NatSigningKeyPem { get; set; }
    public TimeSpan AuthTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan ClientTokenLifetime { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan HostTokenLifetime { get; set; } = TimeSpan.FromHours(24);
    public TimeSpan OwnerTokenLifetime { get; set; } = TimeSpan.FromMinutes(2);
}

public sealed class LoginProtectionOptions
{
    public int MaxFailedAttempts { get; set; } = 5;
    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
    public int MaxTrackedEmails { get; set; } = 100_000;
}

public sealed class RateLimitOptions
{
    public int GlobalPermitLimit { get; set; } = 600;
    public TimeSpan GlobalWindow { get; set; } = TimeSpan.FromMinutes(1);
    public int CreatePermitLimit { get; set; } = 5;
    public TimeSpan CreateWindow { get; set; } = TimeSpan.FromMinutes(1);
    public int ListPermitLimit { get; set; } = 60;
    public TimeSpan ListWindow { get; set; } = TimeSpan.FromMinutes(1);
    public int HeartbeatPermitLimit { get; set; } = 30;
    public TimeSpan HeartbeatWindow { get; set; } = TimeSpan.FromMinutes(1);
    public int DeletePermitLimit { get; set; } = 10;
    public TimeSpan DeleteWindow { get; set; } = TimeSpan.FromMinutes(1);
    public int RegisterPermitLimit { get; set; } = 5;
    public TimeSpan RegisterWindow { get; set; } = TimeSpan.FromMinutes(1);
    public int LoginPermitLimit { get; set; } = 10;
    public TimeSpan LoginWindow { get; set; } = TimeSpan.FromMinutes(1);
}
