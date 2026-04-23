namespace CustomOidcProvider.Models;

public class Client
{
    public string ClientId { get; set; } = "";
    public string? HashedClientSecret { get; set; }
    public bool IsPublic { get; set; }
    public string TokenEndpointAuthMethod { get; set; } = "client_secret_basic";
    public bool AllowRefreshTokens { get; set; }
    public string[] AllowedRedirectUris { get; set; } = [];
    public string[] AllowedScopes { get; set; } = [];
    public string[] AllowedGrantTypes { get; set; } = [];
}
