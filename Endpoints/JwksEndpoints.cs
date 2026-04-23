using CustomOidcProvider.Services;

namespace CustomOidcProvider.Endpoints;

public static class JwksEndpoints
{
    public static IEndpointRouteBuilder MapJwksEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/jwks.json", (IKeyService keyService) =>
            Results.Json(new { keys = new[] { keyService.GetJwk() } }));

        return app;
    }
}
