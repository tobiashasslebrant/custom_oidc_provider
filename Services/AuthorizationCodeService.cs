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

        // Atomically flip Used = true with a single UPDATE WHERE used = false.
        // PostgreSQL executes this as one statement, so only one concurrent
        // request can succeed even under race conditions.
        var updated = await db.AuthorizationCodes
            .Where(c => c.CodeHash == codeHash && !c.Used && c.ExpiresAt > DateTimeOffset.UtcNow)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.Used, true));

        if (updated == 0) return null;

        return await db.AuthorizationCodes.FirstOrDefaultAsync(c => c.CodeHash == codeHash);
    }
}
