namespace MatchmakingService.Models;

public sealed record HostedGameResponse(
    Guid SessionId,
    string PlayerName,
    string GameName,
    string GameType,
    DateTimeOffset CreatedAtUtc)
{
    internal static HostedGameResponse From(HostedGame game) =>
        new(game.SessionId, game.PlayerName, game.GameName, game.GameType, game.CreatedAtUtc);
}
