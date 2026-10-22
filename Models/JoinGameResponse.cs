namespace MatchmakingService.Models;

// Token is the compact NAT client token (role C) for the joined session.
public sealed record JoinGameResponse(string Token);
