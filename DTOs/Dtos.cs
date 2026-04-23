using System.Text.Json.Serialization;

namespace CustomOidcProvider.DTOs;

public class Result<T>
{
    public bool IsSuccess { get; }
    public T? Value { get; }
    public string? Error { get; }
    public string? ErrorDescription { get; }

    private Result(T value) { IsSuccess = true; Value = value; }
    private Result(string error, string? description) { IsSuccess = false; Error = error; ErrorDescription = description; }

    public static Result<T> Ok(T value) => new(value);
    public static Result<T> Fail(string error, string? description = null) => new(error, description);
}

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; } = 3600;

    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }
}

public class OidcError
{
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }
}

public class DiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    [JsonPropertyName("userinfo_endpoint")]
    public required string UserInfoEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    [JsonPropertyName("response_types_supported")]
    public required string[] ResponseTypesSupported { get; init; }

    [JsonPropertyName("grant_types_supported")]
    public required string[] GrantTypesSupported { get; init; }

    [JsonPropertyName("subject_types_supported")]
    public required string[] SubjectTypesSupported { get; init; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required string[] IdTokenSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("scopes_supported")]
    public required string[] ScopesSupported { get; init; }

    [JsonPropertyName("claims_supported")]
    public required string[] ClaimsSupported { get; init; }

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public required string[] TokenEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public required string[] CodeChallengeMethodsSupported { get; init; }

    [JsonPropertyName("end_session_endpoint")]
    public required string EndSessionEndpoint { get; init; }
}
