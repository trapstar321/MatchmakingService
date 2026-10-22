using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

// Per-email brute-force protection, applied identically to existing and unknown emails so lockouts do not reveal
// whether an account exists. Each attempt is counted before the password is checked, so concurrent guesses cannot
// exceed the limit; a successful login clears the count. Works alongside the per-IP login rate limit.
internal sealed class LoginThrottle(TimeProvider clock, IOptions<MatchmakingOptions> options, ILogger<LoginThrottle> logger)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly int _maxFailedAttempts = Math.Max(1, options.Value.LoginProtection.MaxFailedAttempts);
    private readonly TimeSpan _failureWindow = options.Value.LoginProtection.FailureWindow;
    private readonly TimeSpan _lockoutDuration = options.Value.LoginProtection.LockoutDuration;
    private readonly int _maxTrackedEmails = Math.Max(1, options.Value.LoginProtection.MaxTrackedEmails);

    internal bool TryBeginAttempt(string normalizedEmail)
    {
        lock (_gate)
        {
            var now = clock.GetUtcNow();
            if (_entries.TryGetValue(normalizedEmail, out var entry))
            {
                if (entry.LockedUntil > now) return false;
                if (entry.LockedUntil is not null || now - entry.WindowStart >= _failureWindow) entry = new Entry(now, 0, null);
            }
            else
            {
                if (_entries.Count >= _maxTrackedEmails && Prune(now) == 0)
                {
                    // Failing open keeps logins available; the per-IP rate limit still bounds guessing.
                    logger.LogWarning("Login throttle is tracking its maximum number of emails; attempt is not tracked");
                    return true;
                }
                entry = new Entry(now, 0, null);
            }

            var attempts = entry.Attempts + 1;
            _entries[normalizedEmail] = entry with
            {
                Attempts = attempts,
                LockedUntil = attempts >= _maxFailedAttempts ? now + _lockoutDuration : null
            };
            return true;
        }
    }

    internal void RecordSuccess(string normalizedEmail)
    {
        lock (_gate) _entries.Remove(normalizedEmail);
    }

    private int Prune(DateTimeOffset now)
    {
        var stale = _entries.Where(pair => pair.Value.LockedUntil is { } lockedUntil
                ? lockedUntil <= now
                : now - pair.Value.WindowStart >= _failureWindow)
            .Select(pair => pair.Key).ToArray();
        foreach (var key in stale) _entries.Remove(key);
        return stale.Length;
    }

    private sealed record Entry(DateTimeOffset WindowStart, int Attempts, DateTimeOffset? LockedUntil);
}
