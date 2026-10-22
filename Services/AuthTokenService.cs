using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

internal sealed record AuthToken(string Token, DateTimeOffset ExpiresAtUtc);

// Auth tokens are ES256 JWTs that authenticate a player to the MM API only (audience = Tokens:ApiAudience).
// They are never sent to the NAT service, which uses the separate compact host/client token format.
internal sealed class AuthTokenService
{
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false, MapInboundClaims = false };
    private readonly SigningCredentials _credentials;
    private readonly TokenValidationParameters _validation;
    private readonly TimeProvider _clock;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly TimeSpan _lifetime;

    public AuthTokenService(SigningKeys keys, IOptions<MatchmakingOptions> options, TimeProvider clock)
    {
        var settings = options.Value.Tokens;
        if (string.IsNullOrWhiteSpace(settings.Issuer) || string.IsNullOrWhiteSpace(settings.ApiAudience))
            throw new InvalidOperationException("Matchmaking:Tokens:Issuer and ApiAudience are required.");
        if (settings.AuthTokenLifetime <= TimeSpan.Zero)
            throw new InvalidOperationException("Matchmaking:Tokens:AuthTokenLifetime must be positive.");

        // A private provider factory: the process-wide default caches providers by key thumbprint, which could
        // outlive the ECDsa instance owned by SigningKeys.
        var key = new ECDsaSecurityKey(keys.Auth) { CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false } };
        _credentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
        _clock = clock;
        _issuer = settings.Issuer;
        _audience = settings.ApiAudience;
        _lifetime = settings.AuthTokenLifetime;
        _validation = new TokenValidationParameters
        {
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            IssuerSigningKey = key,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidTypes = [JwtConstants.HeaderType],
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            // MM both issues and validates auth tokens, so lifetime is checked against the same injected clock.
            LifetimeValidator = (notBefore, expires, _, _) =>
            {
                var now = _clock.GetUtcNow().UtcDateTime;
                return expires is not null && now < expires && (notBefore is null || notBefore <= now);
            }
        };
    }

    internal AuthToken Create(Guid playerId)
    {
        if (playerId == Guid.Empty) throw new ArgumentException("A player ID is required.", nameof(playerId));
        var now = _clock.GetUtcNow();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds());
        var expires = issuedAt + _lifetime;
        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _audience,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = expires.UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = playerId.ToString("D"),
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N")
            },
            SigningCredentials = _credentials
        });
        return new AuthToken(token, expires);
    }

    // Returns the authenticated permanent player ID, or null for any invalid, expired, or foreign token.
    internal async Task<Guid?> ValidateAsync(string token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var result = await _handler.ValidateTokenAsync(token, _validation);
        if (!result.IsValid ||
            !result.Claims.TryGetValue(JwtRegisteredClaimNames.Sub, out var subject) ||
            !Guid.TryParseExact(subject as string, "D", out var playerId) ||
            playerId == Guid.Empty) return null;
        return playerId;
    }
}
