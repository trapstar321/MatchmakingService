namespace MatchmakingService.Models;

internal sealed record HostedGame(
    Guid SessionId,
    Guid HostPlayerId,
    string PlayerName,
    string GameName,
    string GameType,
    string? Secret,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset LastHeartbeatUtc);
