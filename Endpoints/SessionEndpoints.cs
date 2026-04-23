namespace CustomOidcProvider.Endpoints;

public static class SessionEndpoints
{
    public static IEndpointRouteBuilder MapSessionEndpoints(this IEndpointRouteBuilder app)
    {
        // End-session endpoint per OIDC Session Management spec.
        // In this implementation there is no server-side session state to clear —
        // session lifetime is entirely managed by the relying party's cookie.
        // TODO (production): validate post_logout_redirect_uri against id_token_hint's client.
        app.MapGet("/connect/endsession", (HttpRequest request) =>
        {
            var postLogoutRedirectUri = request.Query["post_logout_redirect_uri"].ToString();
            var state = request.Query["state"].ToString();

            if (string.IsNullOrEmpty(postLogoutRedirectUri))
                return Results.Ok("You have been signed out.");

            var location = string.IsNullOrEmpty(state)
                ? postLogoutRedirectUri
                : $"{postLogoutRedirectUri}?state={Uri.EscapeDataString(state)}";

            return Results.Redirect(location);
        });

        return app;
    }
}
