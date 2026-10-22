using System.Net;
using System.Net.Http.Json;
using Microsoft.Data.Sqlite;
using MatchmakingService.Models;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class AccountsApiTests : IClassFixture<MatchmakingFactory>
{
    private readonly MatchmakingFactory _factory;
    private readonly HttpClient _client;

    public AccountsApiTests(MatchmakingFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Registration_returns_a_player_id_and_login_returns_the_same_id_with_a_new_token()
    {
        var email = TestApi.NewEmail();
        var registered = await TestApi.RegisterAsync(_client, email);
        Assert.NotEqual(Guid.Empty, registered.PlayerId);
        Assert.False(string.IsNullOrWhiteSpace(registered.AuthToken));
        Assert.Equal(_factory.Clock.GetUtcNow().AddHours(1).ToUnixTimeSeconds(), registered.ExpiresAtUtc.ToUnixTimeSeconds());

        var login = await _client.PostAsJsonAsync("/accounts/login", new { email = "  " + email.ToUpperInvariant() + " ", password = TestApi.Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loggedIn = await login.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.Equal(registered.PlayerId, loggedIn!.PlayerId);
        Assert.NotEqual(registered.AuthToken, loggedIn.AuthToken);
    }

    [Fact]
    public async Task Player_id_is_permanent_across_service_restarts()
    {
        var databasePath = MatchmakingFactory.NewDatabasePath();
        try
        {
            var email = TestApi.NewEmail();
            Guid playerId;
            using (var first = new MatchmakingFactory(databasePath))
                playerId = (await TestApi.RegisterAsync(first.CreateClient(), email)).PlayerId;

            using var second = new MatchmakingFactory(databasePath);
            var login = await second.CreateClient().PostAsJsonAsync("/accounts/login", new { email, password = TestApi.Password });
            Assert.Equal(playerId, (await login.Content.ReadFromJsonAsync<AuthResponse>())!.PlayerId);
        }
        finally
        {
            MatchmakingFactory.DeleteDatabase(databasePath);
        }
    }

    [Fact]
    public async Task Duplicate_normalized_emails_are_rejected()
    {
        var local = $"dup-{Guid.NewGuid():N}";
        await TestApi.RegisterAsync(_client, $"{local}@example.com");
        var duplicate = await _client.PostAsJsonAsync("/accounts/register", new { email = $"  {local.ToUpperInvariant()}@EXAMPLE.com ", password = "another password" });
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.DoesNotContain("authToken", await duplicate.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Concurrent_registrations_for_one_email_create_exactly_one_account()
    {
        var email = TestApi.NewEmail();
        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ =>
            _client.PostAsJsonAsync("/accounts/register", new { email, password = TestApi.Password })));

        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Created);
        Assert.Equal(11, responses.Count(response => response.StatusCode == HttpStatusCode.Conflict));
    }

    [Theory]
    [InlineData(null, TestApi.Password)]
    [InlineData("", TestApi.Password)]
    [InlineData("not-an-email", TestApi.Password)]
    [InlineData("a@b@example.com", TestApi.Password)]
    [InlineData("Display Name <x@example.com>", TestApi.Password)]
    [InlineData("x@localhost", TestApi.Password)]
    [InlineData("valid@example.com", null)]
    [InlineData("valid@example.com", "short")]
    [InlineData("valid@example.com", "        ")]
    public async Task Invalid_registration_input_is_rejected(string? email, string? password)
    {
        var response = await _client.PostAsJsonAsync("/accounts/register", new { email, password });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Overlong_passwords_are_rejected_without_hashing()
    {
        var response = await _client.PostAsJsonAsync("/accounts/register", new { email = TestApi.NewEmail(), password = new string('p', AccountService.MaxPasswordLength + 1) });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var boundary = await _client.PostAsJsonAsync("/accounts/register", new { email = TestApi.NewEmail(), password = new string('p', AccountService.MaxPasswordLength) });
        Assert.Equal(HttpStatusCode.Created, boundary.StatusCode);
    }

    [Fact]
    public async Task Invalid_credentials_fail_identically_for_unknown_and_existing_accounts()
    {
        var email = TestApi.NewEmail();
        await TestApi.RegisterAsync(_client, email);

        var wrongPassword = await _client.PostAsJsonAsync("/accounts/login", new { email, password = "wrong password!" });
        var unknownEmail = await _client.PostAsJsonAsync("/accounts/login", new { email = TestApi.NewEmail(), password = "wrong password!" });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownEmail.StatusCode);
        Assert.Equal(await wrongPassword.Content.ReadAsStringAsync(), await unknownEmail.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Passwords_are_stored_only_as_hashes_with_normalized_emails()
    {
        var local = $"Hash-{Guid.NewGuid():N}";
        var registered = await TestApi.RegisterAsync(_client, $"{local}@Example.com");

        await using var connection = new SqliteConnection($"Data Source={_factory.DatabasePath};Mode=ReadOnly;Pooling=False");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT email_normalized, password_hash FROM accounts WHERE player_id = $id";
        command.Parameters.AddWithValue("$id", registered.PlayerId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal($"{local.ToLowerInvariant()}@example.com", reader.GetString(0));
        var hash = reader.GetString(1);
        Assert.NotEqual(TestApi.Password, hash);
        Assert.DoesNotContain(TestApi.Password, hash, StringComparison.Ordinal);
        // ASP.NET Core Identity v3 format marker: version byte 0x01 followed by the PRF identifier.
        Assert.StartsWith("AQAAAA", hash, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Repeated_failures_lock_out_existing_and_unknown_emails_alike_until_the_lockout_ends()
    {
        using var factory = new MatchmakingFactory();
        using var client = factory.CreateClient();
        var email = TestApi.NewEmail();
        var unknown = TestApi.NewEmail();
        await TestApi.RegisterAsync(client, email);

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/accounts/login", new { email, password = "wrong password!" })).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/accounts/login", new { email = unknown, password = "wrong password!" })).StatusCode);
        }

        var locked = await client.PostAsJsonAsync("/accounts/login", new { email, password = TestApi.Password });
        var lockedUnknown = await client.PostAsJsonAsync("/accounts/login", new { email = unknown, password = TestApi.Password });
        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, lockedUnknown.StatusCode);
        Assert.Equal(await locked.Content.ReadAsStringAsync(), await lockedUnknown.Content.ReadAsStringAsync());

        factory.Clock.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/accounts/login", new { email, password = TestApi.Password })).StatusCode);
    }

    [Fact]
    public async Task Successful_login_resets_the_failure_count()
    {
        using var factory = new MatchmakingFactory();
        using var client = factory.CreateClient();
        var email = TestApi.NewEmail();
        await TestApi.RegisterAsync(client, email);

        for (var round = 0; round < 3; round++)
        {
            for (var i = 0; i < 4; i++)
                await client.PostAsJsonAsync("/accounts/login", new { email, password = "wrong password!" });
            Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/accounts/login", new { email, password = TestApi.Password })).StatusCode);
        }
    }
}
