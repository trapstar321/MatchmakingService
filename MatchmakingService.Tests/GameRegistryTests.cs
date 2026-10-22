using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class GameRegistryTests
{
    private static readonly Guid Host = Guid.NewGuid();

    private static GameRegistry CreateRegistry(FakeTimeProvider clock, MatchmakingOptions? options = null) =>
        new(clock, Options.Create(options ?? new MatchmakingOptions()), NullLogger<GameRegistry>.Instance);

    [Fact]
    public void Register_creates_unique_sessions_and_one_time_owner_secrets()
    {
        var registry = CreateRegistry(new FakeTimeProvider());
        var first = registry.Register(Host, "Alice", "Arena", IPAddress.Loopback);
        var second = registry.Register(Host, "Bob", "Co-op", IPAddress.Loopback);

        Assert.NotEqual(first.Game.SessionId, second.Game.SessionId);
        Assert.NotEqual(first.OwnerSecret, second.OwnerSecret);
        Assert.Equal(Host, first.Game.HostPlayerId);
        Assert.Equal("Alice", first.Game.PlayerName);
        Assert.Equal("Arena", first.Game.GameName);
        Assert.Equal("public", first.Game.GameType);
        Assert.Null(first.Game.Secret);
        Assert.Equal(43, first.OwnerSecret.Length);
        Assert.Equal(new[] { first.Game.SessionId, second.Game.SessionId }.Order(), registry.GetActiveGames().Select(g => g.SessionId).Order());
    }

    [Fact]
    public void Owner_secret_authorizes_only_its_session_and_activity_uses_server_clock()
    {
        var clock = new FakeTimeProvider();
        var registry = CreateRegistry(clock);
        var first = registry.Register(Host, "Alice", "Arena", IPAddress.Loopback);
        var second = registry.Register(Host, "Bob", "Co-op", IPAddress.Loopback);

        Assert.Equal(SessionOperationResult.InvalidCredential, registry.Heartbeat(first.Game.SessionId, second.OwnerSecret));
        clock.Advance(TimeSpan.FromSeconds(12));
        Assert.Equal(SessionOperationResult.Success, registry.Heartbeat(first.Game.SessionId, first.OwnerSecret));
        Assert.Equal(clock.GetUtcNow(), Assert.Single(registry.GetActiveGames(), g => g.SessionId == first.Game.SessionId).LastHeartbeatUtc);
        Assert.Equal(SessionOperationResult.Success, registry.Delete(first.Game.SessionId, first.OwnerSecret));
        Assert.Equal(SessionOperationResult.NotFound, registry.Heartbeat(first.Game.SessionId, first.OwnerSecret));
    }

    [Fact]
    public void Expired_session_is_excluded_and_cannot_be_revived()
    {
        var clock = new FakeTimeProvider();
        var registry = CreateRegistry(clock, new MatchmakingOptions { SessionExpirationTimeout = TimeSpan.FromSeconds(30) });
        var registration = registry.Register(Host, "Alice", "Arena", IPAddress.Loopback);
        clock.Advance(TimeSpan.FromSeconds(30));

        Assert.Empty(registry.GetActiveGames());
        Assert.Equal(SessionOperationResult.NotFound, registry.Heartbeat(registration.Game.SessionId, registration.OwnerSecret));
        Assert.Equal(0, registry.RemoveExpiredGames());
    }

    [Fact]
    public async Task Background_cleanup_service_removes_expired_sessions()
    {
        var clock = new FakeTimeProvider();
        var logger = new ExpirationLogger();
        var registry = new GameRegistry(clock,
            Options.Create(new MatchmakingOptions { SessionExpirationTimeout = TimeSpan.FromSeconds(30) }), logger);
        var game = registry.Register(Host, "Alice", "Arena", IPAddress.Loopback);
        var service = new GameCleanupService(registry,
            Options.Create(new MatchmakingOptions { CleanupInterval = TimeSpan.FromSeconds(5) }), clock,
            NullLogger<GameCleanupService>.Instance);

        await service.StartAsync(CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.True(logger.Expired.Wait(TimeSpan.FromSeconds(1)));
        Assert.Empty(registry.GetActiveGames());
        Assert.Equal(0, registry.RemoveExpiredGames());
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Active_and_per_ip_limits_hold_under_concurrent_registration()
    {
        var clock = new FakeTimeProvider();
        var registry = CreateRegistry(clock, new MatchmakingOptions { MaxActiveSessions = 7, MaxSessionsPerIp = 100 });
        var attempts = await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(() =>
        {
            try { return registry.Register(Host, $"p{i}", $"g{i}", IPAddress.Loopback).Game; }
            catch (SessionCapacityExceededException) { return null; }
        })));

        Assert.Equal(7, attempts.Count(game => game is not null));
        Assert.Equal(7, registry.GetActiveGames().Count);

        var perIpRegistry = CreateRegistry(new FakeTimeProvider(), new MatchmakingOptions { MaxSessionsPerIp = 1, MaxActiveSessions = 5 });
        perIpRegistry.Register(Host, "one", "one", IPAddress.Parse("192.0.2.1"));
        Assert.Throws<SessionCapacityExceededException>(() => perIpRegistry.Register(Host, "two", "two", IPAddress.Parse("192.0.2.1")));
        perIpRegistry.Register(Host, "two", "two", IPAddress.Parse("192.0.2.2"));
        Assert.Equal(2, perIpRegistry.GetActiveGames().Count);
    }

    [Fact]
    public async Task Concurrent_heartbeats_deletions_listing_and_cleanup_preserve_registry_consistency()
    {
        var clock = new FakeTimeProvider();
        var registry = CreateRegistry(clock, new MatchmakingOptions
        {
            MaxActiveSessions = 200,
            MaxSessionsPerIp = 200,
            SessionExpirationTimeout = TimeSpan.FromHours(1)
        });
        var sessions = await Task.WhenAll(Enumerable.Range(0, 100).Select(i => Task.Run(() =>
            registry.Register(Host, $"p{i}", $"g{i}", IPAddress.Loopback))));
        var tasks = sessions.Select((session, index) => Task.Run(() =>
        {
            if (index % 3 == 0) registry.Delete(session.Game.SessionId, session.OwnerSecret);
            else registry.Heartbeat(session.Game.SessionId, session.OwnerSecret);
            registry.GetActiveGames();
            registry.RemoveExpiredGames();
        }));

        await Task.WhenAll(tasks);
        var remaining = registry.GetActiveGames();
        Assert.Equal(100 - sessions.Where((_, index) => index % 3 == 0).Count(), remaining.Count);
        Assert.Equal(remaining.Count, remaining.Select(game => game.SessionId).Distinct().Count());

        var raced = registry.Register(Host, "race", "delete-heartbeat", IPAddress.Loopback);
        await Task.WhenAll(
            Task.Run(() => registry.Heartbeat(raced.Game.SessionId, raced.OwnerSecret)),
            Task.Run(() => registry.Delete(raced.Game.SessionId, raced.OwnerSecret)));
        Assert.DoesNotContain(registry.GetActiveGames(), game => game.SessionId == raced.Game.SessionId);
        Assert.Equal(SessionOperationResult.NotFound, registry.Heartbeat(raced.Game.SessionId, raced.OwnerSecret));
    }

    [Fact]
    public void Register_stores_the_host_player_id_and_rejects_a_missing_one()
    {
        var registry = CreateRegistry(new FakeTimeProvider());
        var hostPlayerId = Guid.NewGuid();
        var registration = registry.Register(hostPlayerId, "Alice", "Arena", "private", "join-secret", IPAddress.Loopback);

        Assert.Equal(hostPlayerId, Assert.Single(registry.GetActiveGames()).HostPlayerId);
        Assert.Equal(registration.Game.SessionId, registry.GetActiveGames()[0].SessionId);
        Assert.Throws<ArgumentException>(() => registry.Register(Guid.Empty, "Bob", "Arena", IPAddress.Loopback));
    }

    private sealed class ExpirationLogger : ILogger<GameRegistry>
    {
        public ManualResetEventSlim Expired { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            if (message.StartsWith("Expired hosted game", StringComparison.Ordinal)) Expired.Set();
        }
    }
}
