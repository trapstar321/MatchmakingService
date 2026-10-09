namespace MatchmakingService.Models;

internal sealed record HostedGame(
    Guid SessionId,
    string PlayerName,
    string GameName,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset LastHeartbeatUtc);
