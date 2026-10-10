namespace MatchmakingService.Models;

public sealed record CreateGameRequest(string PlayerName, string GameName, string? GameType = "public", string? Secret = null)
{
    public static bool IsValid(CreateGameRequest request) =>
        !string.IsNullOrWhiteSpace(request.PlayerName) && request.PlayerName!.Trim().Length <= 64 &&
        !string.IsNullOrWhiteSpace(request.GameName) && request.GameName!.Trim().Length <= 100 &&
        (request.GameType == "public" || request.GameType == "private") &&
        (request.GameType != "private" || !string.IsNullOrWhiteSpace(request.Secret));
}
