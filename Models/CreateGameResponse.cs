namespace MatchmakingService.Models;

// OwnerSecret is returned only when a game is created. It is never used by listing responses.
// Token is the compact NAT host token (role H) for this session.
public sealed record CreateGameResponse(
    Guid SessionId,
    Guid HostPlayerId,
    string OwnerSecret,
    string Token,
    string PlayerName,
    string GameName,
    string GameType,
    DateTimeOffset CreatedAtUtc)
{
    internal static CreateGameResponse From(GameRegistration registration, string token) => new(
        registration.Game.SessionId,
        registration.Game.HostPlayerId,
        registration.OwnerSecret,
        token,
        registration.Game.PlayerName,
        registration.Game.GameName,
        registration.Game.GameType,
        registration.Game.CreatedAtUtc);
}
