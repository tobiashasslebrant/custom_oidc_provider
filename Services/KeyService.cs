using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace CustomOidcProvider.Services;

public interface IKeyService
{
    RsaSecurityKey GetPrivateKey();
    RsaSecurityKey GetPublicKey();
    JsonWebKey GetJwk();
    string KeyId { get; }
}

public class KeyService : IKeyService
{
    private readonly RsaSecurityKey _privateKey;
    private readonly RsaSecurityKey _publicKey;
    private readonly JsonWebKey _jwk;

    public string KeyId { get; }

    public KeyService(IConfiguration configuration, ILogger<KeyService> logger)
    {
        var keyPath = configuration["Oidc:RsaKeyPath"]
            ?? Path.Combine(AppContext.BaseDirectory, "keys", "oidc.pem");

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(keyPath))!);

        RSA rsa;
        if (File.Exists(keyPath))
        {
            rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(keyPath));
            logger.LogInformation("Loaded RSA key from {KeyPath}", keyPath);
        }
        else
        {
            rsa = RSA.Create(2048);
            File.WriteAllText(keyPath, rsa.ExportRSAPrivateKeyPem());
            logger.LogInformation("Generated new RSA key at {KeyPath}", keyPath);
        }

        var publicParams = rsa.ExportParameters(false);
        KeyId = ComputeKeyId(publicParams.Modulus!);

        _privateKey = new RsaSecurityKey(rsa) { KeyId = KeyId };

        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(publicParams);
        _publicKey = new RsaSecurityKey(publicRsa) { KeyId = KeyId };

        _jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_publicKey);
        _jwk.Use = JsonWebKeyUseNames.Sig;
        _jwk.Alg = SecurityAlgorithms.RsaSha256;
    }

    public RsaSecurityKey GetPrivateKey() => _privateKey;
    public RsaSecurityKey GetPublicKey() => _publicKey;
    public JsonWebKey GetJwk() => _jwk;

    private static string ComputeKeyId(byte[] modulus)
    {
        var hash = SHA256.HashData(modulus);
        return Base64UrlEncoder.Encode(hash);
    }
}
