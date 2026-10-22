namespace MatchmakingService.Models;

// Token is the compact owner token (role O) of the authenticated player, for the game server that player owns.
public sealed record OwnerTokenResponse(string Token);
