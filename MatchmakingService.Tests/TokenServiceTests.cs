using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class TokenServiceTests
{
    private const string Key = "test-only-signing-key-0123456789abcdef";

    private static TokenService Create(FakeTimeProvider clock, string? key = Key, long expiry = 60) =>
        new(Options.Create(new MatchmakingOptions { TokenSigningKey = key, TokenExpiry = expiry }), clock);

    [Fact]
    public void Verifies_valid_token_and_rejects_tampering_expiry_and_other_keys()
    {
        var clock = new FakeTimeProvider();
        var service = Create(clock);
        var token = service.Create(Guid.NewGuid(), "C");
        Assert.True(service.TryVerify(token, out var claims));
        Assert.Equal("C", claims!.Role);

        var parts = token.Split('.');
        Assert.False(service.TryVerify(parts[0] + "x." + parts[1], out _));
        Assert.False(service.TryVerify(parts[0] + "." + (parts[1][0] == 'A' ? "B" : "A") + parts[1][1..], out _));
        Assert.False(Create(clock, "another-test-signing-key-0123456789").TryVerify(token, out _));

        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.False(service.TryVerify(token, out _));
        Assert.False(service.TryVerify("x.y.z", out _));
        Assert.False(service.TryVerify("!.@@", out _));
    }

    [Fact]
    public void Rejects_missing_signing_key_and_nonpositive_expiry()
    {
        var clock = new FakeTimeProvider();
        Assert.Throws<InvalidOperationException>(() => Create(clock, null));
        Assert.Throws<InvalidOperationException>(() => Create(clock, "short"));
        Assert.Throws<InvalidOperationException>(() => Create(clock, Key, 0));
        Assert.Throws<InvalidOperationException>(() => Create(clock, Key, -1));
    }

    [Fact]
    public void Token_has_session_role_expiry_and_signature_is_hmac_sha256()
    {
        var service = Create(new FakeTimeProvider());
        var token = service.Create(Guid.NewGuid(), "C");
        Assert.True(service.TryVerify(token, out var claims));
        var encodedPayload = token.Split('.')[0].Replace('-', '+').Replace('_', '/');
        encodedPayload += new string('=', (4 - encodedPayload.Length % 4) % 4);
        using var document = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(encodedPayload));
        Assert.Equal(3, document.RootElement.EnumerateObject().Count());
        Assert.False(document.RootElement.TryGetProperty("secretHash", out _));
        Assert.Equal(32, Convert.FromBase64String(token.Split('.')[1].Replace('-', '+').Replace('_', '/') + "=").Length);
    }
    [Fact]
    public void Rejects_signed_payloads_with_invalid_json_fields_roles_or_hashes()
    {
        var service = Create(new FakeTimeProvider());
        Assert.False(service.TryVerify(SignPayload("{"), out _));
        Assert.False(service.TryVerify(SignPayload("{\"session\":\"s\",\"role\":\"X\",\"expires\":9999999999}"), out _));
        Assert.False(service.TryVerify(SignPayload("{\"session\":\" \",\"role\":\"C\",\"expires\":9999999999}"), out _));
        Assert.False(service.TryVerify(SignPayload("{\"role\":\"C\",\"expires\":9999999999}"), out _));
    }

    private static string SignPayload(string json)
    {
        static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var encoded = Encode(System.Text.Encoding.UTF8.GetBytes(json));
        using var hmac = new HMACSHA256(System.Text.Encoding.UTF8.GetBytes(Key));
        return encoded + "." + Encode(hmac.ComputeHash(System.Text.Encoding.ASCII.GetBytes(encoded)));
    }}
