using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

internal sealed class GameCleanupService(
    GameRegistry games,
    IOptions<MatchmakingOptions> options,
    TimeProvider timeProvider,
    ILogger<GameCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Game cleanup service started");
        try
        {
            using var timer = new PeriodicTimer(options.Value.CleanupInterval, timeProvider);
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                games.RemoveExpiredGames();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Cancellation is the normal application shutdown path.
        }
        finally
        {
            logger.LogInformation("Game cleanup service stopped");
        }
    }
}
