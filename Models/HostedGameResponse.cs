namespace MatchmakingService.Models;

// Public listing entry. Never add owner secrets, join secrets, tokens, or account details here.
public sealed record HostedGameResponse(
    Guid SessionId,
    Guid HostPlayerId,
    string PlayerName,
    string GameName,
    string GameType,
    DateTimeOffset CreatedAtUtc)
{
    internal static HostedGameResponse From(HostedGame game) =>
        new(game.SessionId, game.HostPlayerId, game.PlayerName, game.GameName, game.GameType, game.CreatedAtUtc);
}
