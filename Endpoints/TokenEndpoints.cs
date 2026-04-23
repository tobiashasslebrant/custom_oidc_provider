using System.Security.Claims;
using System.Text;
using CustomOidcProvider.Data;
using CustomOidcProvider.DTOs;
using CustomOidcProvider.Models;
using CustomOidcProvider.Services;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Endpoints;

public static class TokenEndpoints
{
    public static IEndpointRouteBuilder MapTokenEndpoints(this IEndpointRouteBuilder app, string issuer)
    {
        app.MapPost("/connect/token", async (
            HttpRequest request,
            AppDbContext db,
            IClientService clientService,
            IAuthorizationCodeService codeService,
            ITokenService tokenService,
            ILogger<Program> logger) =>
        {
            var form = await request.ReadFormAsync();
            var grantType = form["grant_type"].ToString();

            var (client, clientError) = await AuthenticateClientAsync(request, form, clientService);
            if (client is null)
            {
                logger.LogWarning("Client authentication failed: {Error}", clientError);
                return TokenError("invalid_client", clientError);
            }

            return grantType switch
            {
                "authorization_code" => await HandleAuthorizationCodeAsync(form, client, db, codeService, tokenService, logger),
                "refresh_token" => await HandleRefreshTokenAsync(form, client, db, tokenService, logger),
                _ => TokenError("unsupported_grant_type")
            };
        });

        return app;
    }

    private static async Task<IResult> HandleAuthorizationCodeAsync(
        IFormCollection form,
        Client client,
        AppDbContext db,
        IAuthorizationCodeService codeService,
        ITokenService tokenService,
        ILogger logger)
    {
        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(redirectUri) || string.IsNullOrEmpty(codeVerifier))
            return TokenError("invalid_request", "code, redirect_uri, and code_verifier are required.");

        var authCode = await codeService.ConsumeAsync(code);
        if (authCode is null)
        {
            logger.LogWarning("Invalid or replayed authorization code attempted for client {ClientId}", client.ClientId);
            return TokenError("invalid_grant", "Authorization code is invalid, expired, or already used.");
        }

        if (authCode.ClientId != client.ClientId)
        {
            logger.LogWarning("Authorization code client mismatch: expected {Expected}, got {Got}",
                authCode.ClientId, client.ClientId);
            return TokenError("invalid_grant", "Authorization code was issued to a different client.");
        }

        if (authCode.RedirectUri != redirectUri)
            return TokenError("invalid_grant", "redirect_uri does not match.");

        if (!VerifyPkce(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
        {
            logger.LogWarning("PKCE verification failed for client {ClientId}", client.ClientId);
            return TokenError("invalid_grant", "PKCE verification failed.");
        }

        var user = await db.Users.FindAsync(authCode.UserId);
        if (user is null)
            return TokenError("invalid_grant", "User not found.");

        var accessToken = tokenService.IssueAccessToken(user.Id, client.ClientId, authCode.Scopes);
        var idToken = tokenService.IssueIdToken(user.Id, client.ClientId, authCode.Scopes,
            authCode.Nonce, authCode.AuthTime, user);

        string? refreshToken = null;
        if (client.AllowRefreshTokens && client.AllowedGrantTypes.Contains("refresh_token"))
        {
            var (rt, rtHash) = tokenService.GenerateRefreshToken();
            await db.RefreshTokens.AddAsync(new RefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = rtHash,
                ClientId = client.ClientId,
                UserId = user.Id,
                Scopes = authCode.Scopes,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
                Used = false
            });
            await db.SaveChangesAsync();
            refreshToken = rt;
        }

        return Results.Json(new TokenResponse
        {
            AccessToken = accessToken,
            IdToken = idToken,
            RefreshToken = refreshToken,
            ExpiresIn = 3600,
            Scope = string.Join(" ", authCode.Scopes)
        });
    }

    private static async Task<IResult> HandleRefreshTokenAsync(
        IFormCollection form,
        Client client,
        AppDbContext db,
        ITokenService tokenService,
        ILogger logger)
    {
        var rawToken = form["refresh_token"].ToString();
        if (string.IsNullOrEmpty(rawToken))
            return TokenError("invalid_request", "refresh_token is required.");

        var tokenHash = TokenService.ComputeHash(rawToken);

        // Atomically consume the refresh token
        var updated = await db.RefreshTokens
            .Where(t => t.TokenHash == tokenHash && !t.Used && t.ExpiresAt > DateTimeOffset.UtcNow
                        && t.ClientId == client.ClientId)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Used, true));

        if (updated == 0)
        {
            logger.LogWarning("Invalid or replayed refresh token for client {ClientId}", client.ClientId);
            return TokenError("invalid_grant", "Refresh token is invalid, expired, or already used.");
        }

        var existing = await db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
        if (existing is null) return TokenError("invalid_grant");

        var user = await db.Users.FindAsync(existing.UserId);
        if (user is null) return TokenError("invalid_grant", "User not found.");

        var accessToken = tokenService.IssueAccessToken(user.Id, client.ClientId, existing.Scopes);

        // Rotate: issue a new refresh token
        var (newRt, newRtHash) = tokenService.GenerateRefreshToken();
        await db.RefreshTokens.AddAsync(new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = newRtHash,
            ClientId = client.ClientId,
            UserId = user.Id,
            Scopes = existing.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            Used = false
        });
        await db.SaveChangesAsync();

        // Per spec, no ID token on refresh grant
        return Results.Json(new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRt,
            ExpiresIn = 3600,
            Scope = string.Join(" ", existing.Scopes)
        });
    }

    private static async Task<(Client? client, string? error)> AuthenticateClientAsync(
        HttpRequest request,
        IFormCollection form,
        IClientService clientService)
    {
        string? clientId = null;
        string? clientSecret = null;

        // client_secret_basic: Authorization: Basic base64(client_id:client_secret)
        var authHeader = request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader[6..]));
                var colon = decoded.IndexOf(':');
                if (colon > 0)
                {
                    clientId = Uri.UnescapeDataString(decoded[..colon]);
                    clientSecret = Uri.UnescapeDataString(decoded[(colon + 1)..]);
                }
            }
            catch
            {
                return (null, "Invalid Basic authorization header.");
            }
        }
        else
        {
            // client_secret_post
            clientId = form["client_id"].ToString();
            clientSecret = form["client_secret"].ToString();
        }

        if (string.IsNullOrEmpty(clientId))
            return (null, "client_id is required.");

        var client = await clientService.FindAsync(clientId);
        if (client is null)
            return (null, $"Unknown client: {clientId}");

        if (!client.IsPublic)
        {
            if (string.IsNullOrEmpty(clientSecret))
                return (null, "client_secret is required for confidential clients.");
            if (!clientService.ValidateSecret(client, clientSecret))
                return (null, $"Invalid client secret for client {clientId}.");
        }

        return (client, null);
    }

    private static bool VerifyPkce(string codeVerifier, string codeChallenge, string codeChallengeMethod)
    {
        if (codeChallengeMethod != "S256") return false;
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var computed = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(hash);
        return computed == codeChallenge;
    }

    private static IResult TokenError(string error, string? description = null) =>
        Results.Json(new OidcError { Error = error, ErrorDescription = description }, statusCode: 400);
}
