using System.Buffers.Binary;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Models;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

// Test-only ES256 keys, generated in memory for each test run and never written to source control.
internal static class TestKeys
{
    public static readonly ECDsa Auth = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public static readonly ECDsa Nat = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public static readonly string AuthPem = Auth.ExportPkcs8PrivateKeyPem();
    public static readonly string NatPem = Nat.ExportPkcs8PrivateKeyPem();

    public static ECDsa NatPublicKey()
    {
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Nat.ExportSubjectPublicKeyInfo(), out _);
        return key;
    }

    public static MatchmakingOptions Options(Action<TokenOptions>? configure = null)
    {
        var options = new MatchmakingOptions();
        options.Tokens.AuthSigningKeyPem = AuthPem;
        options.Tokens.NatSigningKeyPem = NatPem;
        configure?.Invoke(options.Tokens);
        return options;
    }

    public static SigningKeys SigningKeys(MatchmakingOptions? options = null) =>
        new(Microsoft.Extensions.Options.Options.Create(options ?? Options()), Environment());

    public static IHostEnvironment Environment() => new HostingEnvironment { ContentRootPath = AppContext.BaseDirectory };
}

internal static class TestSettings
{
    public static Dictionary<string, string?> Create(string databasePath) => new()
    {
        ["Matchmaking:DatabasePath"] = databasePath,
        ["Matchmaking:Tokens:Issuer"] = "mm-test-issuer",
        ["Matchmaking:Tokens:ApiAudience"] = "mm-test-api",
        ["Matchmaking:Tokens:AuthSigningKeyPem"] = TestKeys.AuthPem,
        ["Matchmaking:Tokens:NatSigningKeyPem"] = TestKeys.NatPem,
        ["Matchmaking:Tokens:AuthTokenLifetime"] = "01:00:00",
        ["Matchmaking:Tokens:ClientTokenLifetime"] = "00:02:00",
        ["Matchmaking:Tokens:HostTokenLifetime"] = "1.00:00:00",
        ["Matchmaking:MaxActiveSessions"] = "1000",
        ["Matchmaking:MaxSessionsPerIp"] = "1000",
        ["Matchmaking:MaxRequestBodyBytes"] = "2048",
        ["Matchmaking:MaxAuthorizationHeaderBytes"] = "1024",
        ["Matchmaking:RateLimits:GlobalPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:GlobalWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:CreatePermitLimit"] = "1000",
        ["Matchmaking:RateLimits:CreateWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:ListPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:ListWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:HeartbeatPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:HeartbeatWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:DeletePermitLimit"] = "1000",
        ["Matchmaking:RateLimits:DeleteWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:RegisterPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:RegisterWindow"] = "00:01:00",
        ["Matchmaking:RateLimits:LoginPermitLimit"] = "1000",
        ["Matchmaking:RateLimits:LoginWindow"] = "00:01:00"
    };
}

// Hosts the real service with an isolated SQLite file, an injectable clock, and captured logs.
public class MatchmakingFactory : WebApplicationFactory<Program>
{
    private readonly bool _ownsDatabase;

    public MatchmakingFactory() : this(null) { }

    internal MatchmakingFactory(string? databasePath)
    {
        _ownsDatabase = databasePath is null;
        DatabasePath = databasePath ?? NewDatabasePath();
    }

    public string DatabasePath { get; }
    public FakeTimeProvider Clock { get; } = new();
    public CapturingLoggerProvider Logs { get; } = new();

    public static string NewDatabasePath() => Path.Combine(Path.GetTempPath(), "mm-tests", Guid.NewGuid().ToString("N") + ".db");

    protected virtual void ConfigureSettings(Dictionary<string, string?> settings) { }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var settings = TestSettings.Create(DatabasePath);
        ConfigureSettings(settings);
        builder.UseEnvironment("Production");
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.SetMinimumLevel(LogLevel.Trace);
            logging.AddProvider(Logs);
        });
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing || !_ownsDatabase) return;
        DeleteDatabase(DatabasePath);
    }

    public static void DeleteDatabase(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var file in new[] { path, path + "-wal", path + "-shm" })
        {
            try { File.Delete(file); }
            catch (IOException) { }
        }
    }
}

public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _messages = new();

    public string AllText => string.Join('\n', _messages);
    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
    public void Dispose() { }

    private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            owner._messages.Enqueue($"{category} {logLevel}: {formatter(state, exception)} {exception}");
    }
}

internal static class TestApi
{
    public const string Password = "correct horse battery staple";

    public static string NewEmail() => $"player-{Guid.NewGuid():N}@example.com";

    public static async Task<AuthResponse> RegisterAsync(HttpClient client, string? email = null, string password = Password)
    {
        var response = await client.PostAsJsonAsync("/accounts/register", new { email = email ?? NewEmail(), password });
        Assert.True(response.StatusCode == System.Net.HttpStatusCode.Created, await response.Content.ReadAsStringAsync());
        return (await response.Content.ReadFromJsonAsync<AuthResponse>())!;
    }

    public static Task<HttpResponseMessage> PostAsync(HttpClient client, string path, object body, string? bearer)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return client.SendAsync(request);
    }

    public static async Task<CreateGameResponse> CreateGameAsync(HttpClient client, string authToken, object? body = null)
    {
        var response = await PostAsync(client, "/games", body ?? new { playerName = "Host", gameName = "Game", gameType = "public" }, authToken);
        Assert.True(response.StatusCode == System.Net.HttpStatusCode.Created, await response.Content.ReadAsStringAsync());
        return (await response.Content.ReadFromJsonAsync<CreateGameResponse>())!;
    }
}

internal sealed record DecodedNatToken(Guid SessionId, Guid PlayerId, char Role, uint Expires, byte[] Bytes)
{
    public byte[] Payload => Bytes[..NatTokenService.PayloadLength];
    public byte[] Signature => Bytes[NatTokenService.PayloadLength..];
}

// Reference decoder for the compact NAT token layout. Verification lives here, not in MM: the NAT introducer owns it.
internal static class NatTokenReader
{
    public static DecodedNatToken Decode(string token)
    {
        var bytes = Base64Url.DecodeFromChars(token);
        Assert.Equal(NatTokenService.TokenLength, bytes.Length);
        Assert.Equal(token, Base64Url.EncodeToString(bytes));
        return new DecodedNatToken(
            new Guid(bytes.AsSpan(0, 16), bigEndian: true),
            new Guid(bytes.AsSpan(16, 16), bigEndian: true),
            (char)bytes[32],
            BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(33, 4)),
            bytes);
    }

    public static bool Verify(byte[] tokenBytes, ECDsa publicKey) =>
        tokenBytes.Length == NatTokenService.TokenLength &&
        publicKey.VerifyData(tokenBytes.AsSpan(0, NatTokenService.PayloadLength), tokenBytes.AsSpan(NatTokenService.PayloadLength),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public static bool Verify(string token, ECDsa publicKey) => Verify(Base64Url.DecodeFromChars(token), publicKey);
}
