namespace CustomOidcProvider.Models;

public class RefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; } = "";
    public string ClientId { get; set; } = "";
    public Guid UserId { get; set; }
    public string[] Scopes { get; set; } = [];
    public DateTimeOffset ExpiresAt { get; set; }
    public bool Used { get; set; }
}
