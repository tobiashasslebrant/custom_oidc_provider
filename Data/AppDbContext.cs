using CustomOidcProvider.Models;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Client> Clients => Set<Client>();
    public DbSet<User> Users => Set<User>();
    public DbSet<AuthorizationRequest> AuthorizationRequests => Set<AuthorizationRequest>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Client>(e =>
        {
            e.HasKey(c => c.ClientId);
            e.Property(c => c.AllowedRedirectUris).HasColumnType("text[]");
            e.Property(c => c.AllowedScopes).HasColumnType("text[]");
            e.Property(c => c.AllowedGrantTypes).HasColumnType("text[]");
        });

        modelBuilder.Entity<AuthorizationRequest>(e =>
        {
            e.Property(r => r.Scopes).HasColumnType("text[]");
        });

        modelBuilder.Entity<AuthorizationCode>(e =>
        {
            e.HasIndex(c => c.CodeHash).IsUnique();
            e.Property(c => c.Scopes).HasColumnType("text[]");
        });

        modelBuilder.Entity<RefreshToken>(e =>
        {
            e.HasIndex(t => t.TokenHash).IsUnique();
            e.Property(t => t.Scopes).HasColumnType("text[]");
        });
    }
}
