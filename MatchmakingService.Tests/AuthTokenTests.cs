using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MatchmakingService.Models;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class AuthTokenTests : IClassFixture<MatchmakingFactory>
{
    private const string Issuer = "mm-test-issuer";
    private const string Audience = "mm-test-api";
    private readonly MatchmakingFactory _factory;
    private readonly HttpClient _client;

    public AuthTokenTests(MatchmakingFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Auth_token_contains_only_the_expected_claims_and_is_es256_signed()
    {
        var email = TestApi.NewEmail();
        var registered = await TestApi.RegisterAsync(_client, email);
        var token = new JsonWebToken(registered.AuthToken);

        Assert.Equal("ES256", token.Alg);
        Assert.Equal(Issuer, token.Issuer);
        Assert.Equal(Audience, Assert.Single(token.Audiences));
        Assert.Equal(registered.PlayerId.ToString("D"), token.Subject);
        Assert.False(string.IsNullOrEmpty(token.Id));
        Assert.Equal(TimeSpan.FromHours(1), token.ValidTo - token.IssuedAt);
        Assert.Equal(new[] { "aud", "exp", "iat", "iss", "jti", "nbf", "sub" }, token.Claims.Select(claim => claim.Type).Order());
        Assert.DoesNotContain(email, token.EncodedPayload + Base64UrlEncoder.Decode(token.EncodedPayload), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Valid_auth_tokens_are_accepted_and_missing_or_malformed_ones_are_rejected()
    {
        var auth = await TestApi.RegisterAsync(_client);
        Assert.Equal(HttpStatusCode.Created, (await CreateGame(auth.AuthToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame("not-a-jwt")).StatusCode);

        var tampered = auth.AuthToken[..^2] + (auth.AuthToken[^2] == 'A' ? "B" : "A") + auth.AuthToken[^1];
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(tampered)).StatusCode);
    }

    [Fact]
    public async Task Expired_auth_tokens_are_rejected()
    {
        using var factory = new MatchmakingFactory();
        using var client = factory.CreateClient();
        var auth = await TestApi.RegisterAsync(client);

        factory.Clock.Advance(TimeSpan.FromHours(1) - TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Created, (await TestApi.PostAsync(client, "/games", new CreateGameRequest("Host", "Game"), auth.AuthToken)).StatusCode);
        factory.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Unauthorized, (await TestApi.PostAsync(client, "/games", new CreateGameRequest("Host", "Game"), auth.AuthToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TestApi.PostAsync(client, "/join", new { session = Guid.NewGuid() }, auth.AuthToken)).StatusCode);
    }

    [Fact]
    public async Task Tokens_with_wrong_key_issuer_audience_algorithm_or_lifetime_are_rejected()
    {
        var playerId = Guid.NewGuid();
        var now = _factory.Clock.GetUtcNow().UtcDateTime;
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.Equal(HttpStatusCode.Created, (await CreateGame(Mint(TestKeys.Auth, Issuer, Audience, playerId, now))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(Mint(otherKey, Issuer, Audience, playerId, now))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(Mint(TestKeys.Nat, Issuer, Audience, playerId, now))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(Mint(TestKeys.Auth, "someone-else", Audience, playerId, now))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(Mint(TestKeys.Auth, Issuer, "nat-service", playerId, now))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(Mint(TestKeys.Auth, Issuer, Audience, playerId, now.AddMinutes(5)))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(Mint(TestKeys.Auth, Issuer, Audience, playerId, now.AddHours(-2)))).StatusCode);

        var unsigned = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer, Audience = Audience, IssuedAt = now, NotBefore = now, Expires = now.AddHours(1),
            Claims = new Dictionary<string, object> { ["sub"] = playerId.ToString("D") }
        });
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(unsigned)).StatusCode);
    }

    [Fact]
    public async Task Host_and_client_tokens_are_not_accepted_as_auth_tokens()
    {
        var host = await TestApi.RegisterAsync(_client);
        var joiner = await TestApi.RegisterAsync(_client);
        var game = await TestApi.CreateGameAsync(_client, host.AuthToken);
        var join = await TestApi.PostAsync(_client, "/join", new { session = game.SessionId }, joiner.AuthToken);
        var clientToken = (await join.Content.ReadFromJsonAsync<JoinGameResponse>())!.Token;

        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(game.Token)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(clientToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateGame(game.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TestApi.PostAsync(_client, "/join", new { session = game.SessionId }, game.Token)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TestApi.PostAsync(_client, "/join", new { session = game.SessionId }, clientToken)).StatusCode);
    }

    [Fact]
    public async Task Request_body_player_ids_cannot_override_the_authenticated_identity()
    {
        var host = await TestApi.RegisterAsync(_client);
        var joiner = await TestApi.RegisterAsync(_client);
        var impersonated = Guid.NewGuid();

        var game = await TestApi.CreateGameAsync(_client, host.AuthToken, new
        {
            playerName = "Host", gameName = "Game", gameType = "public",
            hostPlayerId = impersonated, playerId = impersonated, sub = impersonated
        });
        Assert.Equal(host.PlayerId, game.HostPlayerId);
        Assert.Equal(host.PlayerId, NatTokenReader.Decode(game.Token).PlayerId);
        var listing = await _client.GetFromJsonAsync<HostedGameResponse[]>("/games");
        Assert.Equal(host.PlayerId, Assert.Single(listing!, entry => entry.SessionId == game.SessionId).HostPlayerId);

        var join = await TestApi.PostAsync(_client, "/join", new { session = game.SessionId, playerId = impersonated }, joiner.AuthToken);
        var clientToken = (await join.Content.ReadFromJsonAsync<JoinGameResponse>())!.Token;
        Assert.Equal(joiner.PlayerId, NatTokenReader.Decode(clientToken).PlayerId);
    }

    private Task<HttpResponseMessage> CreateGame(string? authToken) =>
        TestApi.PostAsync(_client, "/games", new CreateGameRequest("Host", "Game"), authToken);

    private static string Mint(ECDsa key, string issuer, string audience, Guid playerId, DateTime issuedAt) =>
        new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = issuedAt,
            NotBefore = issuedAt,
            Expires = issuedAt.AddHours(1),
            Claims = new Dictionary<string, object> { ["sub"] = playerId.ToString("D") },
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(key) { CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false } },
                SecurityAlgorithms.EcdsaSha256)
        });
}
