using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using MatchmakingService.Services;
using Xunit;

namespace MatchmakingService.Tests;

public sealed class SigningKeysTests
{
    [Fact]
    public void Missing_signing_configuration_fails()
    {
        Assert.Throws<InvalidOperationException>(() => TestKeys.SigningKeys(TestKeys.Options(tokens => tokens.AuthSigningKeyPem = null)));
        Assert.Throws<InvalidOperationException>(() => TestKeys.SigningKeys(TestKeys.Options(tokens => tokens.NatSigningKeyPem = " ")));
        Assert.Throws<InvalidOperationException>(() => TestKeys.SigningKeys(TestKeys.Options(tokens =>
        {
            tokens.NatSigningKeyPem = null;
            tokens.NatSigningKeyPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "missing.pem");
        })));
    }

    [Fact]
    public void Invalid_keys_fail_without_echoing_key_material()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var rsa = RSA.Create(2048);
        var invalid = new[]
        {
            "not a pem",
            TestKeys.Nat.ExportSubjectPublicKeyInfoPem(),
            p384.ExportPkcs8PrivateKeyPem(),
            rsa.ExportPkcs8PrivateKeyPem()
        };

        foreach (var pem in invalid)
        {
            var exception = Assert.Throws<InvalidOperationException>(() => TestKeys.SigningKeys(TestKeys.Options(tokens => tokens.NatSigningKeyPem = pem)));
            Assert.DoesNotContain("BEGIN", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Auth_and_nat_keys_must_be_distinct()
    {
        Assert.Throws<InvalidOperationException>(() => TestKeys.SigningKeys(TestKeys.Options(tokens => tokens.NatSigningKeyPem = TestKeys.AuthPem)));
    }

    [Fact]
    public void Keys_load_from_files_and_the_cli_generates_exports_and_refuses_to_overwrite()
    {
        var directory = Path.Combine(Path.GetTempPath(), "mm-keys-" + Guid.NewGuid().ToString("N"));
        try
        {
            var output = new StringWriter();
            Assert.True(SigningKeyCli.TryRun(["generate-signing-keys", directory], output, TextWriter.Null));
            Assert.DoesNotContain("PRIVATE KEY", output.ToString(), StringComparison.Ordinal);
            foreach (var name in SigningKeyCli.KeyNames)
            {
                Assert.Contains("BEGIN PRIVATE KEY", File.ReadAllText(Path.Combine(directory, name + ".pem")));
                var exported = new StringWriter();
                Assert.True(SigningKeyCli.TryRun(["export-public-key", Path.Combine(directory, name + ".pem")], exported, TextWriter.Null));
                Assert.DoesNotContain("PRIVATE", exported.ToString(), StringComparison.Ordinal);
                Assert.Equal(File.ReadAllText(Path.Combine(directory, name + ".pub.pem")).Trim(), exported.ToString().Trim());
            }

            using var keys = TestKeys.SigningKeys(TestKeys.Options(tokens =>
            {
                tokens.AuthSigningKeyPem = null;
                tokens.NatSigningKeyPem = null;
                tokens.AuthSigningKeyPath = Path.Combine(directory, "mm-auth-signing.pem");
                tokens.NatSigningKeyPath = Path.Combine(directory, "mm-nat-signing.pem");
            }));
            Assert.Equal(256, keys.Nat.KeySize);

            var before = File.ReadAllText(Path.Combine(directory, "mm-nat-signing.pem"));
            var error = new StringWriter();
            Assert.True(SigningKeyCli.TryRun(["generate-signing-keys", directory], TextWriter.Null, error));
            Assert.Contains("Refusing to overwrite", error.ToString());
            Assert.Equal(before, File.ReadAllText(Path.Combine(directory, "mm-nat-signing.pem")));
            Environment.ExitCode = 0;
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Cli_ignores_normal_service_arguments()
    {
        Assert.False(SigningKeyCli.TryRun([], TextWriter.Null, TextWriter.Null));
        Assert.False(SigningKeyCli.TryRun(["--urls", "http://localhost:5080"], TextWriter.Null, TextWriter.Null));
    }

    [Fact]
    public void Service_refuses_to_start_without_valid_signing_keys()
    {
        using var factory = new MissingKeyFactory();
        Assert.ThrowsAny<Exception>(() => factory.CreateClient());
    }

    private sealed class MissingKeyFactory : MatchmakingFactory
    {
        protected override void ConfigureSettings(Dictionary<string, string?> settings)
        {
            settings["Matchmaking:Tokens:NatSigningKeyPem"] = "";
            settings["Matchmaking:Tokens:NatSigningKeyPath"] = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pem");
        }
    }
}
