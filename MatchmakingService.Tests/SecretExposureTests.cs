using System.Net.Http.Json;
using System.Text;
using MatchmakingService.Models;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class SecretExposureTests
{
    [Fact]
    public async Task Full_flow_never_logs_or_returns_private_keys_and_never_logs_credentials()
    {
        using var factory = new MatchmakingFactory();
        using var client = factory.CreateClient();
        var responses = new StringBuilder();
        const string joinSecret = "private-join-secret-sentinel";
        var hostEmail = TestApi.NewEmail();
        var joinerEmail = TestApi.NewEmail();

        var host = await TestApi.RegisterAsync(client, hostEmail);
        var joiner = await TestApi.RegisterAsync(client, joinerEmail);
        var login = await client.PostAsJsonAsync("/accounts/login", new { email = hostEmail, password = TestApi.Password });
        responses.Append(await login.Content.ReadAsStringAsync());
        await client.PostAsJsonAsync("/accounts/login", new { email = joinerEmail, password = "wrong password sentinel" });

        var create = await TestApi.PostAsync(client, "/games", new { playerName = "Host", gameName = "Secret", gameType = "private", secret = joinSecret }, host.AuthToken);
        var createJson = await create.Content.ReadAsStringAsync();
        responses.Append(createJson);
        var game = (await create.Content.ReadFromJsonAsync<CreateGameResponse>())!;
        var join = await TestApi.PostAsync(client, "/join", new { session = game.SessionId, secret = joinSecret }, joiner.AuthToken);
        var joinJson = await join.Content.ReadAsStringAsync();
        responses.Append(joinJson);
        var clientToken = (await join.Content.ReadFromJsonAsync<JoinGameResponse>())!.Token;
        var listing = await client.GetStringAsync("/games");
        responses.Append(listing);

        using var heartbeat = new HttpRequestMessage(HttpMethod.Post, $"/games/{game.SessionId}/heartbeat");
        heartbeat.Headers.Authorization = new("Bearer", game.OwnerSecret);
        await client.SendAsync(heartbeat);

        var logs = factory.Logs.AllText;
        Assert.Contains("Registered hosted game", logs, StringComparison.Ordinal);
        foreach (var secret in new[]
        {
            TestApi.Password, "wrong password sentinel", hostEmail, joinerEmail, joinSecret,
            host.AuthToken, joiner.AuthToken, game.Token, clientToken, game.OwnerSecret
        })
        {
            Assert.DoesNotContain(secret, logs, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var pem in new[] { TestKeys.AuthPem, TestKeys.NatPem })
        {
            // Check every base64 line of the private key PEM, not just the whole block.
            foreach (var line in pem.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 20 && !l.StartsWith("-----")))
            {
                Assert.DoesNotContain(line, logs, StringComparison.Ordinal);
                Assert.DoesNotContain(line, responses.ToString(), StringComparison.Ordinal);
            }
        }
        Assert.DoesNotContain("PRIVATE KEY", logs + responses, StringComparison.Ordinal);

        foreach (var secret in new[] { hostEmail, joinerEmail, joinSecret, game.OwnerSecret, game.Token, clientToken, host.AuthToken })
            Assert.DoesNotContain(secret, listing, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(joinSecret, createJson + joinJson, StringComparison.Ordinal);
    }
}
