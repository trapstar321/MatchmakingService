namespace MatchmakingService.Models;

public sealed record HostedGameResponse(
    Guid SessionId,
    string PlayerName,
    string GameName,
    DateTimeOffset CreatedAtUtc)
{
    internal static HostedGameResponse From(HostedGame game) =>
        new(game.SessionId, game.PlayerName, game.GameName, game.CreatedAtUtc);
}
