using CustomOidcProvider.Data;
using CustomOidcProvider.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Services;

public interface IClientService
{
    Task<Client?> FindAsync(string clientId);
    bool ValidateSecret(Client client, string secret);
}

public class ClientService(AppDbContext db, IPasswordHasher<Client> hasher) : IClientService
{
    public Task<Client?> FindAsync(string clientId) =>
        db.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);

    public bool ValidateSecret(Client client, string secret)
    {
        if (client.HashedClientSecret is null) return false;
        var result = hasher.VerifyHashedPassword(client, client.HashedClientSecret, secret);
        return result != PasswordVerificationResult.Failed;
    }
}
