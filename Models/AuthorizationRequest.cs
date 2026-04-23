namespace CustomOidcProvider.Models;

/// <summary>
/// Server-side storage of a validated authorization request, referenced by
/// the login form via its Id. Prevents param-tampering via hidden form fields.
/// </summary>
public class AuthorizationRequest
{
    public Guid Id { get; set; }
    public string ClientId { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string[] Scopes { get; set; } = [];
    public string ResponseType { get; set; } = "";
    public string? State { get; set; }
    public string? Nonce { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
