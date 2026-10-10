namespace MatchmakingService.Models;

public sealed record JoinGameRequest(string? Session, string? Secret);
