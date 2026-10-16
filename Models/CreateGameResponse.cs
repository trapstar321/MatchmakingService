namespace MatchmakingService.Models;

// OwnerSecret is returned only when a game is created. It is never used by listing responses.
public sealed record CreateGameResponse(
    Guid SessionId,
    string OwnerSecret,
    string Token,
    string PlayerName,
    string GameName,
    string GameType,
    DateTimeOffset CreatedAtUtc)
{
    internal static CreateGameResponse From(GameRegistration registration, string token) => new(
        registration.Game.SessionId,
        registration.OwnerSecret,
        token,
        registration.Game.PlayerName,
        registration.Game.GameName,
        registration.Game.GameType,
        registration.Game.CreatedAtUtc);
}
