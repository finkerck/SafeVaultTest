namespace SafeVault.Core.Security;

public interface IUserCredentialStore
{
    Task<AuthUserRecord?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);
}