using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using MatchmakingService.Models;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class GamesApiTests : IClassFixture<GamesApiFactory>
{
    private readonly GamesApiFactory _factory;
    private readonly HttpClient _client;

    public GamesApiTests(GamesApiFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Ownership_and_public_endpoints_enforce_the_owner_secret()
    {
        var alice = await TestApi.RegisterAsync(_client);
        var bob = await TestApi.RegisterAsync(_client);
        var firstResponse = await Create(alice.AuthToken, " Alice ", " Arena ");
        var secondResponse = await Create(bob.AuthToken, "Bob", "Co-op");
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Created, secondResponse.StatusCode);
        var first = await firstResponse.Content.ReadFromJsonAsync<CreateGameResponse>();
        var second = await secondResponse.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotEqual(first.SessionId, second.SessionId);
        Assert.NotEqual(first.OwnerSecret, second.OwnerSecret);
        Assert.Equal("Alice", first.PlayerName);
        Assert.Equal("Arena", first.GameName);
        Assert.Equal(alice.PlayerId, first.HostPlayerId);

        var listingResponse = await _client.GetAsync("/games");
        var listingJson = await listingResponse.Content.ReadAsStringAsync();
        var listing = await listingResponse.Content.ReadFromJsonAsync<HostedGameResponse[]>();
        Assert.Equal(HttpStatusCode.OK, listingResponse.StatusCode);
        Assert.NotNull(listing);
        Assert.Equal(alice.PlayerId, Assert.Single(listing, game => game.SessionId == first.SessionId).HostPlayerId);
        Assert.Equal(bob.PlayerId, Assert.Single(listing, game => game.SessionId == second.SessionId).HostPlayerId);
        Assert.DoesNotContain(first.OwnerSecret, listingJson, StringComparison.Ordinal);
        Assert.DoesNotContain(first.Token, listingJson, StringComparison.Ordinal);
        Assert.DoesNotContain(alice.AuthToken, listingJson, StringComparison.Ordinal);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(first.OwnerSecret)));
        Assert.DoesNotContain(hash, listingJson, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Heartbeat(first.SessionId)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Delete(first.SessionId)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Heartbeat(first.SessionId, "incorrect-secret")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Delete(first.SessionId, "incorrect-secret")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Heartbeat(first.SessionId, second.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Delete(first.SessionId, second.OwnerSecret)).StatusCode);
        // The host's auth token and host token are not owner secrets.
        Assert.Equal(HttpStatusCode.Forbidden, (await Heartbeat(first.SessionId, alice.AuthToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Delete(first.SessionId, first.Token)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Heartbeat(first.SessionId, first.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Delete(first.SessionId, first.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Delete(first.SessionId, first.OwnerSecret)).StatusCode);
    }

    [Fact]
    public async Task Invalid_requests_and_resource_limits_return_safe_client_errors()
    {
        var auth = (await TestApi.RegisterAsync(_client)).AuthToken;
        foreach (var invalid in new[]
        {
            "{\"playerName\":null,\"gameName\":\"x\"}",
            "{\"playerName\":\"\",\"gameName\":\"x\"}",
            "{\"playerName\":\"   \",\"gameName\":\"x\"}",
            $"{{\"playerName\":\"{new string('p', 65)}\",\"gameName\":\"x\"}}",
            "{\"playerName\":\"p\",\"gameName\":null}",
            "{\"playerName\":\"p\",\"gameName\":\"\"}",
            "{\"playerName\":\"p\",\"gameName\":\"   \"}",
            $"{{\"playerName\":\"p\",\"gameName\":\"{new string('g', 101)}\"}}",
            "{ malformed json"
        })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/games")
            {
                Content = new StringContent(invalid, Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth);
            Assert.Equal(HttpStatusCode.BadRequest, (await _client.SendAsync(request)).StatusCode);
        }

        var normalized = await Create(auth, "  Alice  ", "  Arena  ");
        var created = await normalized.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.Equal(HttpStatusCode.Created, normalized.StatusCode);
        Assert.Equal("Alice", created!.PlayerName);
        Assert.Equal("Arena", created.GameName);

        var boundary = await Create(auth, new string('p', 64), new string('g', 100));
        Assert.Equal(HttpStatusCode.Created, boundary.StatusCode);

        using var oversized = new StringContent(new string('x', 20 * 1024), Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await _client.PostAsync("/games", oversized)).StatusCode);

        using var invalidBodyRequest = new HttpRequestMessage(HttpMethod.Post, $"/games/{created.SessionId}/heartbeat")
        {
            Content = new StringContent("x", Encoding.UTF8, "text/plain")
        };
        invalidBodyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", created.OwnerSecret);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.SendAsync(invalidBodyRequest)).StatusCode);
        using var invalidDelete = new HttpRequestMessage(HttpMethod.Delete, $"/games/{created.SessionId}")
        {
            Content = new StringContent("x", Encoding.UTF8, "text/plain")
        };
        invalidDelete.Headers.Authorization = new AuthenticationHeaderValue("Bearer", created.OwnerSecret);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.SendAsync(invalidDelete)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Heartbeat(Guid.NewGuid(), created.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Delete(Guid.NewGuid(), created.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.PostAsync("/games/not-a-guid/heartbeat", null)).StatusCode);
    }

    [Fact]
    public async Task Expired_sessions_are_not_listed_or_revived()
    {
        var auth = (await TestApi.RegisterAsync(_client)).AuthToken;
        var response = await Create(auth, "Alice", "Arena");
        var registration = await response.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.NotNull(registration);

        _factory.Clock.Advance(TimeSpan.FromSeconds(31));
        var listing = await _client.GetFromJsonAsync<HostedGameResponse[]>("/games");
        Assert.NotNull(listing);
        Assert.DoesNotContain(listing, game => game.SessionId == registration.SessionId);
        Assert.Equal(HttpStatusCode.NotFound,
            (await Heartbeat(registration.SessionId, registration.OwnerSecret)).StatusCode);
    }

    [Fact]
    public async Task Public_and_private_creation_listing_and_join_authorization_work()
    {
        var host = await TestApi.RegisterAsync(_client);
        var joiner = await TestApi.RegisterAsync(_client);
        var publicResponse = await TestApi.PostAsync(_client, "/games", new { playerName = "PublicHost", gameName = "Open", gameType = "public" }, host.AuthToken);
        var publicJson = await publicResponse.Content.ReadAsStringAsync();
        var publicGame = await publicResponse.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.Equal(HttpStatusCode.Created, publicResponse.StatusCode);
        Assert.Equal("public", publicGame!.GameType);
        Assert.DoesNotContain("\"secret\":", publicJson, StringComparison.OrdinalIgnoreCase);

        const string joinSecret = "private-join-secret";
        var privateResponse = await TestApi.PostAsync(_client, "/games", new { playerName = "PrivateHost", gameName = "Closed", gameType = "private", secret = joinSecret }, host.AuthToken);
        var privateJson = await privateResponse.Content.ReadAsStringAsync();
        var privateGame = await privateResponse.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.Equal(HttpStatusCode.Created, privateResponse.StatusCode);
        Assert.Equal("private", privateGame!.GameType);
        Assert.DoesNotContain(joinSecret, privateJson, StringComparison.Ordinal);

        var invalidPrivate = await TestApi.PostAsync(_client, "/games", new { playerName = "Bad", gameName = "No secret", gameType = "private" }, host.AuthToken);
        var invalidType = await TestApi.PostAsync(_client, "/games", new { playerName = "Bad", gameName = "Bad type", gameType = "friends" }, host.AuthToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalidPrivate.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidType.StatusCode);

        var listingResponse = await _client.GetAsync("/games");
        var listingJson = await listingResponse.Content.ReadAsStringAsync();
        var listing = await listingResponse.Content.ReadFromJsonAsync<HostedGameResponse[]>();
        Assert.Equal("public", Assert.Single(listing!, g => g.SessionId == publicGame.SessionId).GameType);
        Assert.Equal("private", Assert.Single(listing!, g => g.SessionId == privateGame.SessionId).GameType);
        Assert.DoesNotContain(joinSecret, listingJson, StringComparison.Ordinal);

        var noSecretPublicJoin = await TestApi.PostAsync(_client, "/join", new { session = publicGame.SessionId }, joiner.AuthToken);
        Assert.True(noSecretPublicJoin.StatusCode == HttpStatusCode.OK, await noSecretPublicJoin.Content.ReadAsStringAsync());
        var publicToken = (await noSecretPublicJoin.Content.ReadFromJsonAsync<JoinGameResponse>())!.Token;
        var publicClaims = NatTokenReader.Decode(publicToken);
        Assert.Equal(NatTokenService.ClientRole, publicClaims.Role);
        Assert.Equal(publicGame.SessionId, publicClaims.SessionId);
        Assert.Equal(joiner.PlayerId, publicClaims.PlayerId);

        var missingSecretJoin = await TestApi.PostAsync(_client, "/join", new { session = privateGame.SessionId }, joiner.AuthToken);
        var badSecretJoin = await TestApi.PostAsync(_client, "/join", new { session = privateGame.SessionId, secret = "wrong" }, joiner.AuthToken);
        Assert.Equal(HttpStatusCode.Forbidden, missingSecretJoin.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, badSecretJoin.StatusCode);
        Assert.DoesNotContain("token", await badSecretJoin.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

        var validPrivateJoin = await TestApi.PostAsync(_client, "/join", new { session = privateGame.SessionId, secret = joinSecret }, joiner.AuthToken);
        var privateToken = (await validPrivateJoin.Content.ReadFromJsonAsync<JoinGameResponse>())!.Token;
        var privateClaims = NatTokenReader.Decode(privateToken);
        Assert.Equal(NatTokenService.ClientRole, privateClaims.Role);
        Assert.Equal(privateGame.SessionId, privateClaims.SessionId);
        Assert.Equal(joiner.PlayerId, privateClaims.PlayerId);
        Assert.DoesNotContain(joinSecret, privateToken, StringComparison.Ordinal);
        Assert.False(privateClaims.Bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(joinSecret)) >= 0);

        var missingGame = await TestApi.PostAsync(_client, "/join", new { session = Guid.NewGuid() }, joiner.AuthToken);
        Assert.Equal(HttpStatusCode.NotFound, missingGame.StatusCode);
        Assert.DoesNotContain("token", await missingGame.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

        var unauthenticatedJoin = await TestApi.PostAsync(_client, "/join", new { session = publicGame.SessionId }, null);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticatedJoin.StatusCode);
        Assert.DoesNotContain("token", await unauthenticatedJoin.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    private Task<HttpResponseMessage> Create(string authToken, string player, string game) =>
        TestApi.PostAsync(_client, "/games", new CreateGameRequest(player, game), authToken);

    private Task<HttpResponseMessage> Heartbeat(Guid sessionId, string? secret = null) =>
        Send(HttpMethod.Post, $"/games/{sessionId}/heartbeat", secret);

    private Task<HttpResponseMessage> Delete(Guid sessionId, string? secret = null) =>
        Send(HttpMethod.Delete, $"/games/{sessionId}", secret);

    private Task<HttpResponseMessage> Send(HttpMethod method, string path, string? secret)
    {
        var request = new HttpRequestMessage(method, path);
        if (secret is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        return _client.SendAsync(request);
    }
}

public sealed class GamesApiFactory : MatchmakingFactory;
