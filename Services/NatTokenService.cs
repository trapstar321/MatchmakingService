using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

// Compact ES256-signed tokens (host role H, client role C, owner role O). H and C are sent to the NAT introducer through
// LiteNetLib's NAT introduction token, which is limited to 256 characters, so they are a fixed binary layout:
//
//   offset  size  field
//   0       16    session ID, RFC 4122 (big-endian) GUID bytes; all zero for O
//   16      16    player ID, RFC 4122 (big-endian) GUID bytes
//   32      1     role, ASCII 'H' (0x48), 'C' (0x43) or 'O' (0x4F)
//   33      4     expiration, unsigned 32-bit big-endian Unix seconds
//   37      64    ES256 signature over bytes 0..36, raw IEEE P1363 R || S
//
// 101 bytes, encoded as unpadded Base64URL = 135 characters. There is no issuer or audience field: this format
// is only meaningful as an MM-issued game token and must never be accepted as an MM API credential.
// O proves the account to a game server the player owns (no session, so it works for local games too); the NAT
// introducer accepts only H and C.
internal sealed class NatTokenService
{
    internal const int GuidLength = 16;
    internal const int PayloadLength = 37;
    internal const int SignatureLength = 64;
    internal const int TokenLength = PayloadLength + SignatureLength;
    internal const int LiteNetLibMaxTokenLength = 256;
    internal const char HostRole = 'H';
    internal const char ClientRole = 'C';
    internal const char OwnerRole = 'O';

    private readonly ECDsa _key;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _hostLifetime;
    private readonly TimeSpan _clientLifetime;
    private readonly TimeSpan _ownerLifetime;

    public NatTokenService(SigningKeys keys, IOptions<MatchmakingOptions> options, TimeProvider clock)
    {
        var settings = options.Value.Tokens;
        if (settings.HostTokenLifetime < TimeSpan.FromSeconds(1) || settings.ClientTokenLifetime < TimeSpan.FromSeconds(1) ||
            settings.OwnerTokenLifetime < TimeSpan.FromSeconds(1))
            throw new InvalidOperationException("Matchmaking:Tokens:HostTokenLifetime, ClientTokenLifetime and OwnerTokenLifetime must be at least one second.");
        _key = keys.Nat;
        _clock = clock;
        _hostLifetime = settings.HostTokenLifetime;
        _clientLifetime = settings.ClientTokenLifetime;
        _ownerLifetime = settings.OwnerTokenLifetime;
    }

    internal string CreateHostToken(Guid sessionId, Guid hostPlayerId) => Create(sessionId, hostPlayerId, HostRole, _hostLifetime);

    internal string CreateClientToken(Guid sessionId, Guid clientPlayerId) => Create(sessionId, clientPlayerId, ClientRole, _clientLifetime);

    internal string CreateOwnerToken(Guid playerId) => Create(Guid.Empty, playerId, OwnerRole, _ownerLifetime);

    private string Create(Guid sessionId, Guid playerId, char role, TimeSpan lifetime)
    {
        var expires = checked(_clock.GetUtcNow().ToUnixTimeSeconds() + (long)lifetime.TotalSeconds);
        Span<byte> token = stackalloc byte[TokenLength];
        WritePayload(token[..PayloadLength], sessionId, playerId, role, expires);
        if (!_key.TrySignData(token[..PayloadLength], token[PayloadLength..], HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out var written) || written != SignatureLength)
            throw new CryptographicException("Unexpected ES256 signature length.");
        return Base64Url.EncodeToString(token);
    }

    // Writes the exact 37-byte signing input. Rejects anything the fixed layout cannot represent faithfully.
    internal static void WritePayload(Span<byte> destination, Guid sessionId, Guid playerId, char role, long expiresUnixSeconds)
    {
        if (destination.Length != PayloadLength) throw new ArgumentException("The payload buffer must be 37 bytes.", nameof(destination));
        if (role is not (HostRole or ClientRole or OwnerRole)) throw new ArgumentException("Unsupported NAT token role.", nameof(role));
        if (role == OwnerRole ? sessionId != Guid.Empty : sessionId == Guid.Empty)
            throw new ArgumentException("H and C tokens require a session ID and O tokens must not have one.", nameof(sessionId));
        if (playerId == Guid.Empty) throw new ArgumentException("A player ID is required.", nameof(playerId));
        if (expiresUnixSeconds is <= 0 or > uint.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(expiresUnixSeconds), "The expiration cannot be represented as unsigned 32-bit Unix seconds.");

        sessionId.TryWriteBytes(destination[..GuidLength], bigEndian: true, out _);
        playerId.TryWriteBytes(destination.Slice(GuidLength, GuidLength), bigEndian: true, out _);
        destination[32] = (byte)role;
        BinaryPrimitives.WriteUInt32BigEndian(destination[33..], (uint)expiresUnixSeconds);
    }
}
