namespace MatchmakingService.Services;

// Runs before any hosted service (including the web server) starts: loads and validates the signing keys and
// applies the account database schema. Any failure stops the host instead of serving with a broken configuration.
internal sealed class StartupInitializer(IServiceProvider services) : IHostedLifecycleService
{
    public Task StartingAsync(CancellationToken cancellationToken)
    {
        services.GetRequiredService<AuthTokenService>();
        services.GetRequiredService<NatTokenService>();
        services.GetRequiredService<AccountStore>().Initialize();
        return Task.CompletedTask;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
