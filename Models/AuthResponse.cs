namespace MatchmakingService.Models;

// AuthToken authenticates the player to the MM API only; it is never sent to the NAT service.
public sealed record AuthResponse(Guid PlayerId, string AuthToken, DateTimeOffset ExpiresAtUtc);
