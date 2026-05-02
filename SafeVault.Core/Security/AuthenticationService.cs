namespace SafeVault.Core.Security;

public sealed class AuthenticationService
{
    private readonly InputValidationService _inputValidationService;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IUserCredentialStore _credentialStore;

    public AuthenticationService(
        InputValidationService inputValidationService,
        IPasswordHasher passwordHasher,
        IUserCredentialStore credentialStore)
    {
        _inputValidationService = inputValidationService;
        _passwordHasher = passwordHasher;
        _credentialStore = credentialStore;
    }

    public async Task<LoginResult> LoginAsync(string? username, string? password, CancellationToken cancellationToken = default)
    {
        if (!_inputValidationService.TryNormalizeUsernameForLookup(username, out var normalizedUsername) || string.IsNullOrWhiteSpace(password))
        {
            return LoginResult.Failure("Invalid username or password.");
        }

        var user = await _credentialStore.GetByUsernameAsync(normalizedUsername, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return LoginResult.Failure("Invalid username or password.");
        }

        var isPasswordValid = _passwordHasher.VerifyPassword(password, user.PasswordHash);
        if (!isPasswordValid)
        {
            return LoginResult.Failure("Invalid username or password.");
        }

        return LoginResult.Success(user.UserId, user.Username, user.Role);
    }
}

public sealed record LoginResult(bool IsAuthenticated, int? UserId, string? Username, UserRole? Role, string? Error)
{
    public static LoginResult Failure(string error) => new(false, null, null, null, error);

    public static LoginResult Success(int userId, string username, UserRole role) => new(true, userId, username, role, null);
}