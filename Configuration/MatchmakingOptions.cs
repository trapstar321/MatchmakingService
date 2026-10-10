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
    public int MaxAuthorizationHeaderBytes { get; set; } = 512;
    public int MaxConcurrentConnections { get; set; } = 256;
    public string? TokenSigningKey { get; set; }
    public long TokenExpiry { get; set; } = 300;
    public RateLimitOptions RateLimits { get; set; } = new();
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
}
