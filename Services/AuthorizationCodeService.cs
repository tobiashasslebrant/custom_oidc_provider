using CustomOidcProvider.Data;
using CustomOidcProvider.Models;
using Microsoft.EntityFrameworkCore;

namespace CustomOidcProvider.Services;

public interface IAuthorizationCodeService
{
    /// <summary>
    /// Atomically marks the code as used and returns it. Returns null if the
    /// code is unknown, already used, or expired.
    /// </summary>
    Task<AuthorizationCode?> ConsumeAsync(string code);
}

public class AuthorizationCodeService(AppDbContext db) : IAuthorizationCodeService
{
    public async Task<AuthorizationCode?> ConsumeAsync(string code)
    {
        var codeHash = TokenService.ComputeHash(code);

        var authCode = await db.AuthorizationCodes
            .FirstOrDefaultAsync(c => c.CodeHash == codeHash && !c.Used && c.ExpiresAt > DateTimeOffset.UtcNow);

        if (authCode is null) return null;

        authCode.Used = true;
        await db.SaveChangesAsync();

        return authCode;
    }
}
