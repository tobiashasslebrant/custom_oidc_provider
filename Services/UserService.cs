using CustomOidcProvider.Data;
using CustomOidcProvider.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Services;

public interface IUserService
{
    Task<User?> AuthenticateAsync(string username, string password);
}

public class UserService(AppDbContext db, IPasswordHasher<User> hasher) : IUserService
{
    public async Task<User?> AuthenticateAsync(string username, string password)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user is null) return null;

        var result = hasher.VerifyHashedPassword(user, user.HashedPassword, password);
        return result != PasswordVerificationResult.Failed ? user : null;
    }
}
