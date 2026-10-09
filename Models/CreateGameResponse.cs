namespace MatchmakingService.Models;

// OwnerSecret is returned only when a game is created. It is never used by listing responses.
public sealed record CreateGameResponse(
    Guid SessionId,
    string OwnerSecret,
    string PlayerName,
    string GameName,
    DateTimeOffset CreatedAtUtc)
{
    internal static CreateGameResponse From(GameRegistration registration) => new(
        registration.Game.SessionId,
        registration.OwnerSecret,
        registration.Game.PlayerName,
        registration.Game.GameName,
        registration.Game.CreatedAtUtc);
}
