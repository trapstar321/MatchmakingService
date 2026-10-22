using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

// Holds MM's ES256 (ECDSA P-256) private keys. Auth tokens and NAT tokens use separate keys so the NAT
// introducer only ever needs the NAT public key. The private keys never leave this process.
internal sealed class SigningKeys : IDisposable
{
    private const string P256Oid = "1.2.840.10045.3.1.7";

    public SigningKeys(IOptions<MatchmakingOptions> options, IHostEnvironment environment)
    {
        var tokens = options.Value.Tokens;
        Auth = Load("Auth", tokens.AuthSigningKeyPem, tokens.AuthSigningKeyPath, environment.ContentRootPath);
        try
        {
            Nat = Load("Nat", tokens.NatSigningKeyPem, tokens.NatSigningKeyPath, environment.ContentRootPath);
            if (Auth.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(Nat.ExportSubjectPublicKeyInfo()))
                throw new InvalidOperationException("Matchmaking:Tokens auth and NAT signing keys must be different keys.");
        }
        catch
        {
            Auth.Dispose();
            Nat?.Dispose();
            throw;
        }
    }

    internal ECDsa Auth { get; }
    internal ECDsa Nat { get; }

    internal static ECDsa LoadPrivateKey(string pem, string name)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            // Exporting private parameters fails for public-only keys, which cannot sign.
            var parameters = key.ExportParameters(includePrivateParameters: true);
            CryptographicOperations.ZeroMemory(parameters.D);
            if (!IsP256(parameters.Curve))
                throw new InvalidOperationException($"Matchmaking:Tokens:{name}SigningKey must be an ECDSA P-256 key.");
            return key;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            key.Dispose();
            // The exception message is generic on purpose: never echo key material.
            throw new InvalidOperationException($"Matchmaking:Tokens:{name}SigningKey is not a valid PEM-encoded ECDSA P-256 private key.");
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static bool IsP256(ECCurve curve) =>
        curve.IsNamed && (curve.Oid.Value == P256Oid || curve.Oid.FriendlyName is "nistP256" or "ECDSA_P256" or "secp256r1");

    private static ECDsa Load(string name, string? pem, string? path, string contentRoot)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException($"Matchmaking:Tokens:{name}SigningKeyPath or {name}SigningKeyPem is required. Generate keys with 'dotnet run -- generate-signing-keys keys'.");
            var fullPath = Path.Combine(contentRoot, path);
            if (!File.Exists(fullPath))
                throw new InvalidOperationException($"Matchmaking:Tokens:{name}SigningKeyPath does not exist: {fullPath}. Generate keys with 'dotnet run -- generate-signing-keys keys'.");
            pem = File.ReadAllText(fullPath);
        }
        return LoadPrivateKey(pem, name);
    }

    public void Dispose()
    {
        Auth.Dispose();
        Nat.Dispose();
    }
}
