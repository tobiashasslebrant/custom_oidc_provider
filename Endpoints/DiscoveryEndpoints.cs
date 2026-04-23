using CustomOidcProvider.DTOs;
using CustomOidcProvider.Services;
using Microsoft.IdentityModel.Tokens;

namespace CustomOidcProvider.Endpoints;

public static class DiscoveryEndpoints
{
    public static IEndpointRouteBuilder MapDiscoveryEndpoints(this IEndpointRouteBuilder app, string issuer)
    {
        app.MapGet("/.well-known/openid-configuration", (IKeyService keyService) =>
            Results.Json(new DiscoveryDocument
            {
                Issuer = issuer,
                AuthorizationEndpoint = $"{issuer}/connect/authorize",
                TokenEndpoint = $"{issuer}/connect/token",
                UserInfoEndpoint = $"{issuer}/connect/userinfo",
                JwksUri = $"{issuer}/.well-known/jwks.json",
                ResponseTypesSupported = ["code"],
                GrantTypesSupported = ["authorization_code", "refresh_token"],
                SubjectTypesSupported = ["public"],
                IdTokenSigningAlgValuesSupported = [SecurityAlgorithms.RsaSha256],
                ScopesSupported = ["openid", "profile", "email"],
                ClaimsSupported = ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                    "given_name", "family_name", "preferred_username", "email"],
                TokenEndpointAuthMethodsSupported = ["client_secret_basic", "client_secret_post"],
                CodeChallengeMethodsSupported = ["S256"],
                EndSessionEndpoint = $"{issuer}/connect/endsession"
            }));

        return app;
    }
}
