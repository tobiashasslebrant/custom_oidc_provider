using CustomOidcProvider.Data;
using CustomOidcProvider.Endpoints;
using CustomOidcProvider.Models;
using CustomOidcProvider.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var issuer = (builder.Configuration["Oidc:Issuer"] ?? "https://localhost:5000").TrimEnd('/');

builder.Services.AddDbContext<AppDbContext>(opts => opts.UseInMemoryDatabase("OidcDb"));


builder.Services.AddSingleton<IKeyService, KeyService>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddScoped<IPasswordHasher<Client>, PasswordHasher<Client>>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IClientService, ClientService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IAuthorizationCodeService, AuthorizationCodeService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IKeyService>((options, keyService) =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            IssuerSigningKey = keyService.GetPublicKey(),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
        options.MapInboundClaims = false;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();

    await SeedDevelopmentDataAsync(scope.ServiceProvider);
}

app.UseAuthentication();
app.UseAuthorization();

app.MapWelcomeEndpoints(issuer);
app.MapDiscoveryEndpoints(issuer);
app.MapJwksEndpoints();
app.MapAuthorizationEndpoints(issuer);
app.MapTokenEndpoints(issuer);
app.MapUserInfoEndpoints();
app.MapSessionEndpoints();

app.Run();

static async Task SeedDevelopmentDataAsync(IServiceProvider services)
{
    var db = services.GetRequiredService<AppDbContext>();
    var clientHasher = services.GetRequiredService<IPasswordHasher<Client>>();
    var userHasher = services.GetRequiredService<IPasswordHasher<User>>();

    if (!await db.Clients.AnyAsync())
    {
        var client = new Client
        {
            ClientId = "test-client",
            IsPublic = false,
            TokenEndpointAuthMethod = "client_secret_basic",
            AllowRefreshTokens = true,
            AllowedRedirectUris =
            [
                "https://localhost:5001",
                "https://localhost:5001/callback",
                "https://localhost:5001/signin-oidc",
                "https://localhost:8080",
                "https://localhost:8080/callback",
                "https://localhost:8080/signin-oidc",
                "https://api.descope.com",
                "https://api.descope.com/oauth2/v1/callback",
                "https://api.descope.com/oauth2/v1/signin-oidc"

            ],
            AllowedScopes = ["openid", "profile", "email"],
            AllowedGrantTypes = ["authorization_code", "refresh_token"],
            HashedClientSecret = clientHasher.HashPassword(new Client(), "secret123")
        };
        await db.Clients.AddAsync(client);
    }

    if (!await db.Users.AnyAsync())
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = "testuser",
            Email = "testuser@example.com",
            GivenName = "Test",
            FamilyName = "User"
        };
        user.HashedPassword = userHasher.HashPassword(user, "Password1!");
        await db.Users.AddAsync(user);
    }

    await db.SaveChangesAsync();
}

