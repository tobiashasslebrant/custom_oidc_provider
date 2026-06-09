using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CustomOidcProvider.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace CustomOidcProvider.Services;

public interface ITokenService
{
    string IssueAccessToken(Guid userId, string clientId, string[] scopes);
    string IssueIdToken(Guid userId, string clientId, string[] scopes, string? nonce, DateTimeOffset authTime, User user);
    (string token, string hash) GenerateRefreshToken();
    (string code, string hash) GenerateAuthorizationCode();
}

public class TokenService(IKeyService keyService, IConfiguration configuration) : ITokenService
{
    private readonly string _issuer = (configuration["Oidc:Issuer"] ?? "https://localhost:5000").TrimEnd('/');

    public string IssueAccessToken(Guid userId, string clientId, string[] scopes)
    {
        var now = DateTimeOffset.UtcNow;
        var lifetime = configuration.GetValue("Oidc:AccessTokenLifetimeSeconds", 3600);
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([
                new Claim("sub", userId.ToString()),
                new Claim("client_id", clientId),
                new Claim("scope", string.Join(" ", scopes))
            ]),
            Issuer = _issuer,
            Audience = clientId,
            IssuedAt = now.UtcDateTime,
            Expires = now.AddSeconds(lifetime).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                keyService.GetPrivateKey(),
                SecurityAlgorithms.RsaSha256)
        };

        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }

    public string IssueIdToken(Guid userId, string clientId, string[] scopes, string? nonce, DateTimeOffset authTime, User user)
    {
        var now = DateTimeOffset.UtcNow;
        var claims = new List<Claim>
        {
            new("sub", userId.ToString()),
            new("auth_time", authTime.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (nonce is not null)
            claims.Add(new Claim("nonce", nonce));

        if (scopes.Contains("profile"))
        {
            if (user.GivenName is not null) claims.Add(new Claim("given_name", user.GivenName));
            if (user.FamilyName is not null) claims.Add(new Claim("family_name", user.FamilyName));
            claims.Add(new Claim("preferred_username", user.Username));

            claims.Add(new Claim(
                type: "RpOriginalAttributes",
                value: JsonSerializer.Serialize(user.RpOriginalAttributes),
                valueType: "json"));
        }

        if (scopes.Contains("email"))
            claims.Add(new Claim("email", user.Email));

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = _issuer,
            Audience = clientId,
            IssuedAt = now.UtcDateTime,
            Expires = now.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                keyService.GetPrivateKey(),
                SecurityAlgorithms.RsaSha256)
        };

        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }

    public (string token, string hash) GenerateRefreshToken()
    {
        var token = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var hash = ComputeHash(token);
        return (token, hash);
    }

    public (string code, string hash) GenerateAuthorizationCode()
    {
        var code = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var hash = ComputeHash(code);
        return (code, hash);
    }

    public static string ComputeHash(string value) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
