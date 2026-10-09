namespace MatchmakingService.Models;

public sealed record CreateGameRequest(string PlayerName, string GameName)
{
    public static bool IsValid(CreateGameRequest request) =>
        !string.IsNullOrWhiteSpace(request.PlayerName) && request.PlayerName!.Trim().Length <= 64 &&
        !string.IsNullOrWhiteSpace(request.GameName) && request.GameName!.Trim().Length <= 100;
}
