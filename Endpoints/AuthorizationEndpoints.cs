using CustomOidcProvider.Data;
using CustomOidcProvider.DTOs;
using CustomOidcProvider.Models;
using CustomOidcProvider.Services;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Endpoints;

public static class AuthorizationEndpoints
{
    public static IEndpointRouteBuilder MapAuthorizationEndpoints(this IEndpointRouteBuilder app, string issuer)
    {
        // Step 1: Validate the authorization request, persist it, return login form.
        app.MapGet("/connect/authorize", async (
            HttpRequest request,
            AppDbContext db,
            IClientService clientService,
            ILogger<Program> logger) =>
        {
            var q = request.Query;
            var responseType = q["response_type"].ToString();
            var clientId = q["client_id"].ToString();
            var redirectUri = q["redirect_uri"].ToString();
            var scope = q["scope"].ToString();
            var state = q["state"].ToString();
            var nonce = q["nonce"].ToString();
            var codeChallenge = q["code_challenge"].ToString();
            var codeChallengeMethod = q["code_challenge_method"].ToString();

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
                return Results.BadRequest("client_id and redirect_uri are required.");

            var client = await clientService.FindAsync(clientId);
            if (client is null)
                return Results.BadRequest("Unknown client_id.");

            // Exact-match redirect URI
            if (!client.AllowedRedirectUris.Any(a => redirectUri.StartsWith(a, StringComparison.InvariantCultureIgnoreCase)))
            {
                logger.LogWarning("Invalid redirect_uri {RedirectUri} for client {ClientId}", redirectUri, clientId);
                return Results.BadRequest("Invalid redirect_uri.");
            }

            if (responseType != "code")
                return RedirectWithError(redirectUri, state, "unsupported_response_type");

            var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (!scopes.Contains("openid"))
                return RedirectWithError(redirectUri, state, "invalid_scope", "openid scope is required.");

            var invalidScopes = scopes.Except(client.AllowedScopes).ToArray();
            if (invalidScopes.Length > 0)
                return RedirectWithError(redirectUri, state, "invalid_scope",
                    $"Scopes not allowed: {string.Join(", ", invalidScopes)}");

            if (!client.AllowedGrantTypes.Contains("authorization_code"))
                return RedirectWithError(redirectUri, state, "unauthorized_client");

            // PKCE is mandatory
            if (string.IsNullOrEmpty(codeChallenge))
                return RedirectWithError(redirectUri, state, "invalid_request", "code_challenge is required.");
            if (codeChallengeMethod != "S256")
                return RedirectWithError(redirectUri, state, "invalid_request",
                    "Only S256 code_challenge_method is supported.");

            var authRequest = new AuthorizationRequest
            {
                Id = Guid.NewGuid(),
                ClientId = clientId,
                RedirectUri = redirectUri,
                Scopes = scopes,
                ResponseType = responseType,
                State = string.IsNullOrEmpty(state) ? null : state,
                Nonce = string.IsNullOrEmpty(nonce) ? null : nonce,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
            };

            await db.AuthorizationRequests.AddAsync(authRequest);
            await db.SaveChangesAsync();

            return Results.Content(RenderLoginForm(authRequest.Id, issuer), "text/html");
        });

        // Step 2: Process login credentials, issue authorization code, redirect.
        app.MapPost("/connect/authorize", async (
            HttpRequest request,
            AppDbContext db,
            IUserService userService,
            ITokenService tokenService,
            ILogger<Program> logger) =>
        {
            var form = await request.ReadFormAsync();
            var requestIdStr = form["request_id"].ToString();
            var username = form["username"].ToString();
            var password = form["password"].ToString();

            if (!Guid.TryParse(requestIdStr, out var requestId))
                return Results.BadRequest("Invalid request_id.");

            var authRequest = await db.AuthorizationRequests
                .FirstOrDefaultAsync(r => r.Id == requestId && r.ExpiresAt > DateTimeOffset.UtcNow);

            if (authRequest is null)
                return Results.BadRequest("Authorization request not found or expired.");

            // Remove the request to prevent replay
            db.AuthorizationRequests.Remove(authRequest);

            var user = await userService.AuthenticateAsync(username, password);
            if (user is null)
            {
                logger.LogWarning("Failed login attempt for username {Username} (request {RequestId})", username, requestId);
                // Re-save a new request so the user can retry
                var retryRequest = new AuthorizationRequest
                {
                    Id = Guid.NewGuid(),
                    ClientId = authRequest.ClientId,
                    RedirectUri = authRequest.RedirectUri,
                    Scopes = authRequest.Scopes,
                    ResponseType = authRequest.ResponseType,
                    State = authRequest.State,
                    Nonce = authRequest.Nonce,
                    CodeChallenge = authRequest.CodeChallenge,
                    CodeChallengeMethod = authRequest.CodeChallengeMethod,
                    ExpiresAt = authRequest.ExpiresAt
                };
                await db.AuthorizationRequests.AddAsync(retryRequest);
                await db.SaveChangesAsync();
                return Results.Content(RenderLoginForm(retryRequest.Id, issuer, "Invalid username or password."), "text/html");
            }

            var (code, codeHash) = tokenService.GenerateAuthorizationCode();
            var authCode = new AuthorizationCode
            {
                Id = Guid.NewGuid(),
                CodeHash = codeHash,
                ClientId = authRequest.ClientId,
                UserId = user.Id,
                RedirectUri = authRequest.RedirectUri,
                Scopes = authRequest.Scopes,
                CodeChallenge = authRequest.CodeChallenge!,
                CodeChallengeMethod = authRequest.CodeChallengeMethod!,
                Nonce = authRequest.Nonce,
                AuthTime = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
                Used = false
            };

            await db.AuthorizationCodes.AddAsync(authCode);
            await db.SaveChangesAsync();

            var redirectUrl = BuildRedirectUrl(authRequest.RedirectUri, authRequest.State, code);
            return Results.Redirect(redirectUrl);
        });

        return app;
    }

    private static IResult RedirectWithError(string redirectUri, string? state, string error, string? description = null)
    {
        var url = $"{redirectUri}?error={Uri.EscapeDataString(error)}";
        if (description is not null) url += $"&error_description={Uri.EscapeDataString(description)}";
        if (state is not null) url += $"&state={Uri.EscapeDataString(state)}";
        return Results.Redirect(url);
    }

    private static string BuildRedirectUrl(string redirectUri, string? state, string code)
    {
        var url = $"{redirectUri}?code={Uri.EscapeDataString(code)}";
        if (state is not null) url += $"&state={Uri.EscapeDataString(state)}";
        return url;
    }

    private static string RenderLoginForm(Guid requestId, string issuer, string? errorMessage = null) => $$"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sign In</title>
            <style>
                body { font-family: system-ui, sans-serif; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; background:#f0f2f5; }
                .card { background:#fff; padding:2rem; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.15); width:100%; max-width:360px; }
                h1 { margin:0 0 1.5rem; font-size:1.4rem; }
                label { display:block; margin-bottom:.25rem; font-size:.9rem; font-weight:500; }
                input { width:100%; box-sizing:border-box; padding:.6rem .75rem; border:1px solid #ccc; border-radius:4px; margin-bottom:1rem; font-size:1rem; }
                button { width:100%; padding:.7rem; background:#0070f3; color:#fff; border:none; border-radius:4px; font-size:1rem; cursor:pointer; }
                button:hover { background:#005cc5; }
                .error { color:#c0392b; font-size:.9rem; margin-bottom:1rem; }
                .issuer { color:#888; font-size:.75rem; margin-top:1rem; text-align:center; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Sign In</h1>
                {{(errorMessage is not null ? $"<p class=\"error\">{System.Net.WebUtility.HtmlEncode(errorMessage)}</p>" : "")}}
                <form method="post" action="/connect/authorize">
                    <input type="hidden" name="request_id" value="{{requestId}}" />
                    <label for="username">Username</label>
                    <input id="username" type="text" name="username" autocomplete="username" required autofocus />
                    <label for="password">Password</label>
                    <input id="password" type="password" name="password" autocomplete="current-password" required />
                    <button type="submit">Sign In</button>
                </form>
                <p class="issuer">{{System.Net.WebUtility.HtmlEncode(issuer)}}</p>
            </div>
        </body>
        </html>
        """;
}
