using System.Buffers.Text;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using MatchmakingService.Models;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class NatTokenTests
{
    private static readonly Guid Session = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static readonly Guid Player = Guid.Parse("f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f");

    private static NatTokenService Create(FakeTimeProvider clock, Action<Configuration.TokenOptions>? configure = null)
    {
        var options = TestKeys.Options(configure);
        return new NatTokenService(TestKeys.SigningKeys(options), Options.Create(options), clock);
    }

    [Fact]
    public void Host_token_has_role_H_ids_lifetime_and_a_valid_signature()
    {
        var clock = new FakeTimeProvider();
        var token = Create(clock, tokens => tokens.HostTokenLifetime = TimeSpan.FromHours(24)).CreateHostToken(Session, Player);
        var decoded = NatTokenReader.Decode(token);

        Assert.Equal('H', decoded.Role);
        Assert.Equal(Session, decoded.SessionId);
        Assert.Equal(Player, decoded.PlayerId);
        Assert.Equal(clock.GetUtcNow().AddHours(24).ToUnixTimeSeconds(), decoded.Expires);
        using var publicKey = TestKeys.NatPublicKey();
        Assert.True(NatTokenReader.Verify(token, publicKey));
    }

    [Fact]
    public void Client_token_has_role_C_ids_lifetime_and_a_valid_signature()
    {
        var clock = new FakeTimeProvider();
        var token = Create(clock, tokens => tokens.ClientTokenLifetime = TimeSpan.FromSeconds(90)).CreateClientToken(Session, Player);
        var decoded = NatTokenReader.Decode(token);

        Assert.Equal('C', decoded.Role);
        Assert.Equal(Session, decoded.SessionId);
        Assert.Equal(Player, decoded.PlayerId);
        Assert.Equal(clock.GetUtcNow().ToUnixTimeSeconds() + 90, decoded.Expires);
        using var publicKey = TestKeys.NatPublicKey();
        Assert.True(NatTokenReader.Verify(token, publicKey));
    }

    [Fact]
    public void Owner_token_has_role_O_an_empty_session_the_player_lifetime_and_a_valid_signature()
    {
        var clock = new FakeTimeProvider();
        var token = Create(clock, tokens => tokens.OwnerTokenLifetime = TimeSpan.FromSeconds(75)).CreateOwnerToken(Player);
        var decoded = NatTokenReader.Decode(token);

        Assert.Equal('O', decoded.Role);
        Assert.Equal(Guid.Empty, decoded.SessionId);
        Assert.Equal(Player, decoded.PlayerId);
        Assert.Equal(clock.GetUtcNow().ToUnixTimeSeconds() + 75, decoded.Expires);
        Assert.Equal(135, token.Length);
        using var publicKey = TestKeys.NatPublicKey();
        Assert.True(NatTokenReader.Verify(token, publicKey));
    }

    [Fact]
    public void Owner_tokens_have_no_session_and_host_and_client_tokens_require_one()
    {
        Assert.Throws<ArgumentException>(() => NatTokenService.WritePayload(new byte[37], Session, Player, 'O', 1_800_000_000));
        Assert.Throws<ArgumentException>(() => NatTokenService.WritePayload(new byte[37], Guid.Empty, Player, 'C', 1_800_000_000));
        Assert.Throws<ArgumentException>(() => Create(new FakeTimeProvider()).CreateOwnerToken(Guid.Empty));
    }

    [Fact]
    public void Owner_token_lifetimes_shorter_than_one_second_are_rejected()
    {
        Assert.Throws<InvalidOperationException>(() => Create(new FakeTimeProvider(), tokens => tokens.OwnerTokenLifetime = TimeSpan.FromMilliseconds(500)));
    }

    [Fact]
    public async Task Api_issues_owner_tokens_only_to_authenticated_players()
    {
        using var factory = new MatchmakingFactory();
        using var client = factory.CreateClient();
        var player = await TestApi.RegisterAsync(client);
        using var publicKey = TestKeys.NatPublicKey();

        var response = await TestApi.PostAsync(client, "/accounts/owner-token", new { }, player.AuthToken);
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        var token = (await response.Content.ReadFromJsonAsync<OwnerTokenResponse>())!.Token;
        var decoded = NatTokenReader.Decode(token);
        Assert.Equal(('O', Guid.Empty, player.PlayerId), (decoded.Role, decoded.SessionId, decoded.PlayerId));
        Assert.Equal(factory.Clock.GetUtcNow().AddMinutes(2).ToUnixTimeSeconds(), decoded.Expires);
        Assert.True(NatTokenReader.Verify(token, publicKey));

        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await TestApi.PostAsync(client, "/accounts/owner-token", new { }, null)).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await TestApi.PostAsync(client, "/accounts/owner-token", new { }, token)).StatusCode);
    }

    [Fact]
    public void Token_is_101_bytes_with_a_64_byte_raw_signature_and_fits_the_LiteNetLib_limit()
    {
        var token = Create(new FakeTimeProvider()).CreateHostToken(Session, Player);
        var decoded = NatTokenReader.Decode(token);

        Assert.Equal(101, decoded.Bytes.Length);
        Assert.Equal(37, decoded.Payload.Length);
        Assert.Equal(64, decoded.Signature.Length);
        Assert.Equal(135, token.Length);
        Assert.True(token.Length <= NatTokenService.LiteNetLibMaxTokenLength);
        Assert.All(token, c => Assert.True(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
    }

    [Fact]
    public void Guids_use_rfc4122_big_endian_byte_order_and_round_trip()
    {
        var payload = new byte[NatTokenService.PayloadLength];
        NatTokenService.WritePayload(payload, Session, Player, 'C', 1_800_000_000);

        Assert.Equal(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), payload[..16]);
        Assert.Equal(Convert.FromHexString("F0E1D2C3B4A5968778695A4B3C2D1E0F"), payload[16..32]);
        Assert.Equal((byte)'C', payload[32]);
        Assert.Equal(Convert.FromHexString("6B49D200"), payload[33..37]);
        Assert.Equal(Session, new Guid(payload.AsSpan(0, 16), bigEndian: true));
        Assert.Equal(Player, new Guid(payload.AsSpan(16, 16), bigEndian: true));
    }

    [Fact]
    public void Changing_any_signed_byte_or_the_signature_invalidates_the_token()
    {
        var bytes = Base64Url.DecodeFromChars(Create(new FakeTimeProvider()).CreateHostToken(Session, Player));
        using var publicKey = TestKeys.NatPublicKey();
        Assert.True(NatTokenReader.Verify(bytes, publicKey));

        for (var i = 0; i < bytes.Length; i++)
        {
            var tampered = (byte[])bytes.Clone();
            tampered[i] ^= 0x01;
            Assert.False(NatTokenReader.Verify(tampered, publicKey), $"Byte {i} was not covered by the signature.");
        }
    }

    [Fact]
    public void Host_and_client_roles_cannot_be_substituted()
    {
        using var publicKey = TestKeys.NatPublicKey();
        var service = Create(new FakeTimeProvider());
        var host = Base64Url.DecodeFromChars(service.CreateHostToken(Session, Player));
        var client = Base64Url.DecodeFromChars(service.CreateClientToken(Session, Player));

        host[32] = (byte)'C';
        client[32] = (byte)'H';
        Assert.False(NatTokenReader.Verify(host, publicKey));
        Assert.False(NatTokenReader.Verify(client, publicKey));
    }

    [Fact]
    public void Tokens_do_not_verify_with_the_auth_signing_key()
    {
        var token = Create(new FakeTimeProvider()).CreateClientToken(Session, Player);
        Assert.False(NatTokenReader.Verify(token, TestKeys.Auth));
    }

    [Theory]
    [InlineData('X')]
    [InlineData('h')]
    [InlineData('\0')]
    public void Invalid_roles_are_rejected(char role)
    {
        Assert.Throws<ArgumentException>(() => NatTokenService.WritePayload(new byte[37], Session, Player, role, 1_800_000_000));
    }

    [Fact]
    public void Empty_ids_and_wrong_buffer_sizes_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => NatTokenService.WritePayload(new byte[37], Guid.Empty, Player, 'H', 1_800_000_000));
        Assert.Throws<ArgumentException>(() => NatTokenService.WritePayload(new byte[37], Session, Guid.Empty, 'H', 1_800_000_000));
        Assert.Throws<ArgumentException>(() => NatTokenService.WritePayload(new byte[36], Session, Player, 'H', 1_800_000_000));
        var service = Create(new FakeTimeProvider());
        Assert.Throws<ArgumentException>(() => service.CreateHostToken(Session, Guid.Empty));
        Assert.Throws<ArgumentException>(() => service.CreateClientToken(Guid.Empty, Player));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(4_294_967_296L)]
    [InlineData(long.MaxValue)]
    public void Unrepresentable_expirations_are_rejected(long expires)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => NatTokenService.WritePayload(new byte[37], Session, Player, 'H', expires));
    }

    [Fact]
    public void Maximum_uint32_expiration_is_accepted_and_later_expirations_fail_at_issuance()
    {
        var payload = new byte[37];
        NatTokenService.WritePayload(payload, Session, Player, 'H', uint.MaxValue);
        Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, payload[33..]);

        var nearLimit = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(uint.MaxValue - 60));
        var service = Create(nearLimit, tokens => tokens.HostTokenLifetime = TimeSpan.FromHours(1));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.CreateHostToken(Session, Player));
    }

    [Fact]
    public void Lifetimes_shorter_than_one_second_are_rejected()
    {
        Assert.Throws<InvalidOperationException>(() => Create(new FakeTimeProvider(), tokens => tokens.HostTokenLifetime = TimeSpan.Zero));
        Assert.Throws<InvalidOperationException>(() => Create(new FakeTimeProvider(), tokens => tokens.ClientTokenLifetime = TimeSpan.FromMilliseconds(500)));
    }

    [Fact]
    public async Task Api_issues_host_tokens_on_create_and_client_tokens_on_join_with_configured_lifetimes()
    {
        using var factory = new MatchmakingFactory();
        using var client = factory.CreateClient();
        var host = await TestApi.RegisterAsync(client);
        var joiner = await TestApi.RegisterAsync(client);
        using var publicKey = TestKeys.NatPublicKey();
        var now = factory.Clock.GetUtcNow();

        var game = await TestApi.CreateGameAsync(client, host.AuthToken);
        var hostToken = NatTokenReader.Decode(game.Token);
        Assert.Equal(('H', game.SessionId, host.PlayerId), (hostToken.Role, hostToken.SessionId, hostToken.PlayerId));
        Assert.Equal(now.AddDays(1).ToUnixTimeSeconds(), hostToken.Expires);
        Assert.True(NatTokenReader.Verify(game.Token, publicKey));

        var join = await TestApi.PostAsync(client, "/join", new { session = game.SessionId }, joiner.AuthToken);
        var clientToken = (await join.Content.ReadFromJsonAsync<JoinGameResponse>())!.Token;
        var decoded = NatTokenReader.Decode(clientToken);
        Assert.Equal(('C', game.SessionId, joiner.PlayerId), (decoded.Role, decoded.SessionId, decoded.PlayerId));
        Assert.Equal(now.AddMinutes(2).ToUnixTimeSeconds(), decoded.Expires);
        Assert.True(NatTokenReader.Verify(clientToken, publicKey));
    }
}
