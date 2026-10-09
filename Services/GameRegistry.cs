using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Models;

namespace MatchmakingService.Services;

internal enum SessionOperationResult
{
    Success,
    NotFound,
    InvalidCredential
}

internal sealed class SessionCapacityExceededException : Exception { }

internal sealed class GameRegistry(
    TimeProvider timeProvider,
    IOptions<MatchmakingOptions> options,
    ILogger<GameRegistry> logger)
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, Session> _games = [];
    private readonly TimeSpan _expirationTimeout = options.Value.SessionExpirationTimeout;
    private readonly int _maxActiveSessions = Math.Max(1, options.Value.MaxActiveSessions);
    private readonly int _maxSessionsPerIp = Math.Max(1, options.Value.MaxSessionsPerIp);

    internal GameRegistration Register(string playerName, string gameName, IPAddress? sourceAddress)
    {
        lock (_gate)
        {
            var now = timeProvider.GetUtcNow();
            RemoveExpired(now);
            var sourceKey = GetSourceKey(sourceAddress);
            if (_games.Count >= _maxActiveSessions ||
                _games.Values.Count(session => session.SourceKey == sourceKey) >= _maxSessionsPerIp)
            {
                throw new SessionCapacityExceededException();
            }

            var secretBytes = RandomNumberGenerator.GetBytes(32);
            var secret = Convert.ToBase64String(secretBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var secretHash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
            CryptographicOperations.ZeroMemory(secretBytes);
            var game = new HostedGame(Guid.NewGuid(), playerName, gameName, now, now);
            while (_games.ContainsKey(game.SessionId))
            {
                game = game with { SessionId = Guid.NewGuid() };
            }

            _games.Add(game.SessionId, new Session(game, secretHash, sourceKey));
            logger.LogInformation("Registered hosted game {SessionId}", game.SessionId);
            return new GameRegistration(game, secret);
        }
    }

    internal IReadOnlyList<HostedGame> GetActiveGames()
    {
        lock (_gate)
        {
            var now = timeProvider.GetUtcNow();
            return _games.Values.Select(session => session.Game)
                .Where(game => !IsExpired(game, now)).ToArray();
        }
    }

    internal SessionOperationResult Heartbeat(Guid sessionId, string ownerSecret)
    {
        lock (_gate)
        {
            if (!_games.TryGetValue(sessionId, out var session)) return SessionOperationResult.NotFound;
            if (IsExpired(session.Game, timeProvider.GetUtcNow()))
            {
                Remove(sessionId, session, "Expired hosted game");
                return SessionOperationResult.NotFound;
            }
            if (!HasValidSecret(ownerSecret, session.OwnerSecretHash)) return SessionOperationResult.InvalidCredential;

            var updated = session.Game with { LastHeartbeatUtc = timeProvider.GetUtcNow() };
            _games[sessionId] = session with { Game = updated };
            return SessionOperationResult.Success;
        }
    }

    internal SessionOperationResult Delete(Guid sessionId, string ownerSecret)
    {
        lock (_gate)
        {
            if (!_games.TryGetValue(sessionId, out var session)) return SessionOperationResult.NotFound;
            if (IsExpired(session.Game, timeProvider.GetUtcNow()))
            {
                Remove(sessionId, session, "Expired hosted game");
                return SessionOperationResult.NotFound;
            }
            if (!HasValidSecret(ownerSecret, session.OwnerSecretHash)) return SessionOperationResult.InvalidCredential;

            Remove(sessionId, session, "Removed hosted game");
            return SessionOperationResult.Success;
        }
    }

    internal int RemoveExpiredGames()
    {
        lock (_gate) return RemoveExpired(timeProvider.GetUtcNow());
    }

    private int RemoveExpired(DateTimeOffset now)
    {
        var expired = _games.Values.Where(session => IsExpired(session.Game, now)).ToArray();
        foreach (var session in expired) Remove(session.Game.SessionId, session, "Expired hosted game");
        return expired.Length;
    }

    private void Remove(Guid sessionId, Session session, string message)
    {
        _games.Remove(sessionId);
        logger.LogInformation("{Event} {SessionId}", message, sessionId);
    }

    private bool IsExpired(HostedGame game, DateTimeOffset now) =>
        now - game.LastHeartbeatUtc >= _expirationTimeout;

    private static bool HasValidSecret(string secret, byte[] expectedHash)
    {
        var suppliedHash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return CryptographicOperations.FixedTimeEquals(suppliedHash, expectedHash);
    }

    private static string GetSourceKey(IPAddress? address)
    {
        if (address is null) return "unknown";
        return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
    }

    private sealed record Session(HostedGame Game, byte[] OwnerSecretHash, string SourceKey);
}
