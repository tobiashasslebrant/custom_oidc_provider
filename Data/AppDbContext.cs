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
        modelBuilder.Entity<Client>(e => e.HasKey(c => c.ClientId));

        modelBuilder.Entity<AuthorizationCode>(e =>
            e.HasIndex(c => c.CodeHash).IsUnique());

        modelBuilder.Entity<RefreshToken>(e =>
            e.HasIndex(t => t.TokenHash).IsUnique());
    }
}
