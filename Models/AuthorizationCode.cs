namespace CustomOidcProvider.Models;

public class AuthorizationCode
{
    public Guid Id { get; set; }
    public string CodeHash { get; set; } = "";
    public string ClientId { get; set; } = "";
    public Guid UserId { get; set; }
    public string RedirectUri { get; set; } = "";
    public string[] Scopes { get; set; } = [];
    public string CodeChallenge { get; set; } = "";
    public string CodeChallengeMethod { get; set; } = "";
    public string? Nonce { get; set; }
    public DateTimeOffset AuthTime { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public bool Used { get; set; }
}
