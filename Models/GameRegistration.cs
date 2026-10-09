namespace MatchmakingService.Models;

internal sealed record GameRegistration(HostedGame Game, string OwnerSecret);
