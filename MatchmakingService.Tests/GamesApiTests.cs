using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Models;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class GamesApiTests : IClassFixture<GamesApiFactory>
{
    private readonly HttpClient _client;

    public GamesApiTests(GamesApiFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task Ownership_and_public_endpoints_enforce_the_owner_secret()
    {
        var firstResponse = await Create(" Alice ", " Arena ");
        var secondResponse = await Create("Bob", "Co-op");
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

        var listingResponse = await _client.GetAsync("/games");
        var listingJson = await listingResponse.Content.ReadAsStringAsync();
        var listing = await listingResponse.Content.ReadFromJsonAsync<HostedGameResponse[]>();
        Assert.Equal(HttpStatusCode.OK, listingResponse.StatusCode);
        Assert.NotNull(listing);
        Assert.Contains(listing, game => game.SessionId == first.SessionId);
        Assert.DoesNotContain(first.OwnerSecret, listingJson, StringComparison.Ordinal);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(first.OwnerSecret)));
        Assert.DoesNotContain(hash, listingJson, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Heartbeat(first.SessionId)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Delete(first.SessionId)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Heartbeat(first.SessionId, "incorrect-secret")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Delete(first.SessionId, "incorrect-secret")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Heartbeat(first.SessionId, second.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Delete(first.SessionId, second.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Heartbeat(first.SessionId, first.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Delete(first.SessionId, first.OwnerSecret)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Delete(first.SessionId, first.OwnerSecret)).StatusCode);
    }

    [Fact]
    public async Task Invalid_requests_and_resource_limits_return_safe_client_errors()
    {
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
            using var content = new StringContent(invalid, Encoding.UTF8, "application/json");
            Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync("/games", content)).StatusCode);
        }

        var normalized = await _client.PostAsJsonAsync("/games", new CreateGameRequest("  Alice  ", "  Arena  "));
        var created = await normalized.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.Equal(HttpStatusCode.Created, normalized.StatusCode);
        Assert.Equal("Alice", created!.PlayerName);
        Assert.Equal("Arena", created.GameName);

        var boundary = await _client.PostAsJsonAsync("/games",
            new CreateGameRequest(new string('p', 64), new string('g', 100)));
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
        var response = await Create("Alice", "Arena");
        var registration = await response.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.NotNull(registration);

        GamesApiFactory.Clock.Advance(TimeSpan.FromSeconds(31));
        var listing = await _client.GetFromJsonAsync<HostedGameResponse[]>("/games");
        Assert.NotNull(listing);
        Assert.DoesNotContain(listing, game => game.SessionId == registration.SessionId);
        Assert.Equal(HttpStatusCode.NotFound,
            (await Heartbeat(registration.SessionId, registration.OwnerSecret)).StatusCode);
    }

    private Task<HttpResponseMessage> Create(string player, string game) =>
        _client.PostAsJsonAsync("/games", new CreateGameRequest(player, game));

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

public sealed class GamesApiFactory : WebApplicationFactory<Program>
{
    public static FakeTimeProvider Clock { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production");
        builder.ConfigureLogging(logging => logging.ClearProviders());
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(TestSettings.HighLimits));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            services.PostConfigure<MatchmakingOptions>(options =>
            {
                options.MaxActiveSessions = 1000;
                options.MaxSessionsPerIp = 1000;
                options.RateLimits.GlobalPermitLimit = 1000;
                options.RateLimits.CreatePermitLimit = 1000;
                options.RateLimits.ListPermitLimit = 1000;
                options.RateLimits.HeartbeatPermitLimit = 1000;
                options.RateLimits.DeletePermitLimit = 1000;
            });
        });
    }
}

internal static class TestSettings
{
    public static readonly Dictionary<string, string?> HighLimits = new()
    {
        ["Matchmaking:MaxActiveSessions"] = "1000",
        ["Matchmaking:MaxSessionsPerIp"] = "1000",
        ["Matchmaking:MaxRequestBodyBytes"] = "2048",
        ["Matchmaking:MaxAuthorizationHeaderBytes"] = "512",
        ["Matchmaking:RateLimits:GlobalPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:GlobalWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:CreatePermitLimit"] = "1000",
        ["Matchmaking:RateLimits:CreateWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:ListPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:ListWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:HeartbeatPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:HeartbeatWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:DeletePermitLimit"] = "1000",
        ["Matchmaking:RateLimits:DeleteWindow"] = "00:01:00"
    };
}
