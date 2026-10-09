using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
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

public sealed class SecurityControlsTests
{
    [Fact]
    public async Task Configured_create_rate_limit_returns_429()
    {
        using var factory = new RateLimitFactory();
        using var client = factory.CreateClient();

        var first = await CreateWithForwardedIp(client, "one");
        var second = await CreateWithForwardedIp(client, "two");
        var third = await CreateWithForwardedIp(client, "three");

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);

        var firstGame = await first.Content.ReadFromJsonAsync<CreateGameResponse>();
        var secondGame = await second.Content.ReadFromJsonAsync<CreateGameResponse>();
        Assert.NotNull(firstGame);
        Assert.NotNull(secondGame);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/games")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("/games")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, await OwnedRequest(client, HttpMethod.Post, firstGame, "heartbeat"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await OwnedRequest(client, HttpMethod.Post, firstGame, "heartbeat"));
        Assert.Equal(HttpStatusCode.NoContent, await OwnedRequest(client, HttpMethod.Delete, secondGame));
        Assert.Equal(HttpStatusCode.TooManyRequests, await OwnedRequest(client, HttpMethod.Delete, secondGame));
    }

    [Fact]
    public async Task Concurrent_http_creates_cannot_exceed_the_active_session_limit()
    {
        using var factory = new CapacityFactory();
        using var client = factory.CreateClient();
        var requests = Enumerable.Range(0, 20).Select(i =>
            client.PostAsJsonAsync("/games", new CreateGameRequest($"p{i}", $"g{i}"))).ToArray();
        var responses = await Task.WhenAll(requests);

        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Created);
        Assert.Equal(19, responses.Count(response => response.StatusCode == HttpStatusCode.ServiceUnavailable));
    }

    [Fact]
    public async Task Unexpected_exception_returns_generic_error_without_exception_details()
    {
        using var factory = new FaultingClockFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/games");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("An unexpected error occurred.", body, StringComparison.Ordinal);
        Assert.DoesNotContain("internal-secret-sentinel", body, StringComparison.Ordinal);
        Assert.DoesNotContain("InvalidOperationException", body, StringComparison.Ordinal);
        Assert.DoesNotContain("MatchmakingService", body, StringComparison.Ordinal);
    }

    private class ConfiguredFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(TestSettings.HighLimits));
        }
    }

    private sealed class RateLimitFactory : ConfiguredFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services => services.PostConfigure<MatchmakingOptions>(options =>
            {
                options.RateLimits.GlobalPermitLimit = 100;
                options.RateLimits.CreatePermitLimit = 2;
                options.RateLimits.CreateWindow = TimeSpan.FromMinutes(1);
                options.RateLimits.ListPermitLimit = 1;
                options.RateLimits.ListWindow = TimeSpan.FromMinutes(1);
                options.RateLimits.HeartbeatPermitLimit = 1;
                options.RateLimits.HeartbeatWindow = TimeSpan.FromMinutes(1);
                options.RateLimits.DeletePermitLimit = 1;
                options.RateLimits.DeleteWindow = TimeSpan.FromMinutes(1);
            }));
        }
    }

    private sealed class CapacityFactory : ConfiguredFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services => services.PostConfigure<MatchmakingOptions>(options =>
            {
                options.MaxActiveSessions = 1;
                options.MaxSessionsPerIp = 100;
                options.RateLimits.GlobalPermitLimit = 100;
                options.RateLimits.CreatePermitLimit = 100;
            }));
        }
    }

    private sealed class FaultingClockFactory : ConfiguredFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider, FaultingTimeProvider>();
            });
        }
    }

    private sealed class FaultingTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => throw new InvalidOperationException("internal-secret-sentinel");
    }

    private static async Task<HttpResponseMessage> CreateWithForwardedIp(HttpClient client, string playerName)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/games")
        {
            Content = JsonContent.Create(new CreateGameRequest(playerName, "game"))
        };
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"198.51.100.{playerName.Length}");
        return await client.SendAsync(request);
    }

    private static async Task<HttpStatusCode> OwnedRequest(HttpClient client, HttpMethod method,
        CreateGameResponse game, string? action = null)
    {
        var path = action is null ? $"/games/{game.SessionId}" : $"/games/{game.SessionId}/{action}";
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", game.OwnerSecret);
        return (await client.SendAsync(request)).StatusCode;
    }
}
