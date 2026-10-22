using System.Net.Mail;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace MatchmakingService.Services;

internal enum LoginStatus
{
    Success,
    InvalidCredentials,
    LockedOut
}

internal sealed record LoginResult(LoginStatus Status, Guid PlayerId = default);

internal sealed class AccountService(AccountStore store, LoginThrottle throttle, TimeProvider clock, ILogger<AccountService> logger)
{
    internal const int MinPasswordLength = 8;
    internal const int MaxPasswordLength = 128;
    private const int MaxEmailLength = 254;

    // ASP.NET Core Identity's hasher (PBKDF2-HMAC-SHA512, per-hash random salt, versioned format).
    private static readonly PasswordHasher<object> Hasher = new();
    private static readonly object HashSubject = new();
    // Verified against for unknown emails so a missing account takes about as long as a wrong password.
    private static readonly Lazy<string> DummyHash = new(() => Hasher.HashPassword(HashSubject, Guid.NewGuid().ToString("N")));

    // Trims, Unicode-normalizes (NFC) and lower-cases an address. Only simple single-'@' addresses are accepted.
    internal static bool TryNormalizeEmail(string? email, out string normalized)
    {
        normalized = string.Empty;
        var candidate = email?.Trim();
        if (string.IsNullOrEmpty(candidate) || candidate.Length > MaxEmailLength) return false;
        candidate = candidate.Normalize(NormalizationForm.FormC);
        if (candidate.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return false;

        var at = candidate.IndexOf('@');
        if (at <= 0 || at > 64 || at != candidate.LastIndexOf('@')) return false;
        var domain = candidate[(at + 1)..];
        if (domain.Length == 0 || !domain.Contains('.') || domain.StartsWith('.') || domain.EndsWith('.') || domain.Contains("..")) return false;
        if (!MailAddress.TryCreate(candidate, out var parsed) || parsed.Address != candidate) return false;

        normalized = candidate.ToLowerInvariant();
        return true;
    }

    internal static bool IsValidPassword(string? password) =>
        password is { Length: >= MinPasswordLength and <= MaxPasswordLength } && !string.IsNullOrWhiteSpace(password);

    // Returns the new permanent player ID, or null when the normalized email is already registered.
    internal async Task<Guid?> RegisterAsync(string normalizedEmail, string password, CancellationToken cancellationToken)
    {
        var account = new AccountRecord(Guid.NewGuid(), normalizedEmail, Hasher.HashPassword(HashSubject, password));
        var result = await store.CreateAsync(account, clock.GetUtcNow(), cancellationToken);
        if (result == CreateAccountResult.DuplicateEmail) return null;
        logger.LogInformation("Registered account {PlayerId}", account.PlayerId);
        return account.PlayerId;
    }

    internal async Task<LoginResult> LoginAsync(string normalizedEmail, string password, CancellationToken cancellationToken)
    {
        if (!throttle.TryBeginAttempt(normalizedEmail)) return new LoginResult(LoginStatus.LockedOut);

        var account = await store.FindByEmailAsync(normalizedEmail, cancellationToken);
        var verification = Hasher.VerifyHashedPassword(HashSubject, account?.PasswordHash ?? DummyHash.Value, password);
        if (account is null || verification == PasswordVerificationResult.Failed)
            return new LoginResult(LoginStatus.InvalidCredentials);

        throttle.RecordSuccess(normalizedEmail);
        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            await store.UpdatePasswordHashAsync(account.PlayerId, Hasher.HashPassword(HashSubject, password), cancellationToken);
        return new LoginResult(LoginStatus.Success, account.PlayerId);
    }
}
