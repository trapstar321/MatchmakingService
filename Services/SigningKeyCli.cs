using System.Security.Cryptography;

namespace MatchmakingService.Services;

// Key-management commands that run instead of the web host:
//   dotnet run -- generate-signing-keys <directory>   creates mm-auth-signing.pem / mm-nat-signing.pem (+ .pub.pem)
//   dotnet run -- export-public-key <private-key.pem> prints the public key PEM (e.g. for the NAT introducer)
internal static class SigningKeyCli
{
    internal static readonly string[] KeyNames = ["mm-auth-signing", "mm-nat-signing"];

    internal static bool TryRun(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length == 0 || args[0] is not ("generate-signing-keys" or "export-public-key")) return false;
        if (args.Length != 2)
        {
            error.WriteLine("Usage: generate-signing-keys <directory> | export-public-key <private-key.pem>");
            Environment.ExitCode = 2;
            return true;
        }

        try
        {
            if (args[0] == "generate-signing-keys") Generate(args[1], output);
            else output.Write(ExportPublicKey(File.ReadAllText(args[1])));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            error.WriteLine(exception.Message);
            Environment.ExitCode = 1;
        }
        return true;
    }

    internal static string ExportPublicKey(string privateKeyPem)
    {
        using var key = SigningKeys.LoadPrivateKey(privateKeyPem, "Exported");
        return key.ExportSubjectPublicKeyInfoPem() + Environment.NewLine;
    }

    private static void Generate(string directory, TextWriter output)
    {
        Directory.CreateDirectory(directory);
        foreach (var name in KeyNames)
        {
            var privatePath = Path.Combine(directory, name + ".pem");
            var publicPath = Path.Combine(directory, name + ".pub.pem");
            if (File.Exists(privatePath) || File.Exists(publicPath))
                throw new InvalidOperationException($"Refusing to overwrite existing key {privatePath}. Existing tokens depend on it.");
        }

        foreach (var name in KeyNames)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privatePath = Path.Combine(directory, name + ".pem");
            WriteNew(privatePath, key.ExportPkcs8PrivateKeyPem() + Environment.NewLine, ownerOnly: true);
            WriteNew(Path.Combine(directory, name + ".pub.pem"), key.ExportSubjectPublicKeyInfoPem() + Environment.NewLine, ownerOnly: false);
            output.WriteLine($"Wrote {privatePath} (private, keep secret) and its .pub.pem public key.");
        }
    }

    private static void WriteNew(string path, string contents, bool ownerOnly)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (ownerOnly && !OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var writer = new StreamWriter(path, System.Text.Encoding.ASCII, options);
        writer.Write(contents);
    }
}
