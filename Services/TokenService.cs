using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

internal sealed record AuthorizationTokenClaims(string Session, string Role, long Expires);

internal sealed class TokenService
{
    private readonly byte[] _key;
    private readonly long _expiry;
    private readonly TimeProvider _clock;

    public TokenService(IOptions<MatchmakingOptions> options, TimeProvider clock)
    {
        var settings = options.Value;
        if (string.IsNullOrWhiteSpace(settings.TokenSigningKey) || Encoding.UTF8.GetByteCount(settings.TokenSigningKey) < 32)
            throw new InvalidOperationException("Matchmaking:TokenSigningKey is required and must contain at least 32 UTF-8 bytes.");
        if (settings.TokenExpiry <= 0)
            throw new InvalidOperationException("Matchmaking:TokenExpiry must be a positive number of seconds.");
        _key = Encoding.UTF8.GetBytes(settings.TokenSigningKey);
        _expiry = settings.TokenExpiry;
        _clock = clock;
    }

    internal string Create(Guid session, string role)
    {
        if (role is not ("H" or "C")) throw new ArgumentException("Unsupported token role.", nameof(role));
        var expires = checked(_clock.GetUtcNow().ToUnixTimeSeconds() + _expiry);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { session = session.ToString(), role, expires });
        var encodedPayload = Base64UrlEncode(payload);
        using var hmac = new HMACSHA256(_key);
        return encodedPayload + "." + Base64UrlEncode(hmac.ComputeHash(Encoding.ASCII.GetBytes(encodedPayload)));
    }

    internal bool TryVerify(string? token, out AuthorizationTokenClaims? claims)
    {
        claims = null;
        if (string.IsNullOrEmpty(token)) return false;
        var parts = token.Split('.');
        if (parts.Length != 2 || !TryBase64UrlDecode(parts[0], out var payload) || !TryBase64UrlDecode(parts[1], out var signature)) return false;
        using var hmac = new HMACSHA256(_key);
        var expected = hmac.ComputeHash(Encoding.ASCII.GetBytes(parts[0]));
        if (signature.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(signature, expected)) return false;
        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("session", out var sessionElement) || sessionElement.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(sessionElement.GetString()) ||
                !root.TryGetProperty("role", out var roleElement) || roleElement.ValueKind != JsonValueKind.String ||
                roleElement.GetString() is not ("H" or "C") ||
                !root.TryGetProperty("expires", out var expiresElement) || !expiresElement.TryGetInt64(out var expires)) return false;
            if (expires <= _clock.GetUtcNow().ToUnixTimeSeconds()) return false;
            claims = new AuthorizationTokenClaims(sessionElement.GetString()!, roleElement.GetString()!, expires);
            return true;
        }
        catch (JsonException) { return false; }
    }

    private static string Base64UrlEncode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryBase64UrlDecode(string value, out byte[] bytes)
    {
        bytes = [];
        if (value.Length == 0 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) || value.Length % 4 == 1) return false;
        try
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            base64 += new string('=', (4 - base64.Length % 4) % 4);
            bytes = Convert.FromBase64String(base64);
            return true;
        }
        catch (FormatException) { return false; }
    }
}
