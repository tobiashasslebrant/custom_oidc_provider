using CustomOidcProvider.Data;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Endpoints;

public static class UserInfoEndpoints
{
    public static IEndpointRouteBuilder MapUserInfoEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/connect/userinfo", HandleUserInfoAsync).RequireAuthorization();
        app.MapPost("/connect/userinfo", HandleUserInfoAsync).RequireAuthorization();

        return app;
    }

    private static async Task<IResult> HandleUserInfoAsync(HttpContext ctx, AppDbContext db)
    {
        var principal = ctx.User;
        var subClaim = principal.FindFirst("sub")?.Value;
        if (subClaim is null || !Guid.TryParse(subClaim, out var userId))
            return Results.Unauthorized();

        var user = await db.Users.FindAsync(userId);
        if (user is null) return Results.Unauthorized();

        var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
        var scopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var claims = new Dictionary<string, object> { ["sub"] = user.Id.ToString() };

        if (scopes.Contains("profile"))
        {
            claims["preferred_username"] = user.Username;
            if (user.GivenName is not null) claims["given_name"] = user.GivenName;
            if (user.FamilyName is not null) claims["family_name"] = user.FamilyName;
        }

        if (scopes.Contains("email"))
            claims["email"] = user.Email;

        return Results.Json(claims);
    }
}
