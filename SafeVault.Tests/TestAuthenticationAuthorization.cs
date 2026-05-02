using SafeVault.Core.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthenticationAuthorization
{
    [Test]
    public async Task InvalidPassword_ShouldFailAuthentication()
    {
        var inputValidationService = new InputValidationService();
        var passwordHasher = new BCryptPasswordHasher();
        var storedHash = passwordHasher.HashPassword("CorrectP@ss123");

        var store = new InMemoryCredentialStore(new AuthUserRecord(1, "alice", storedHash, UserRole.User, true));
        var authenticationService = new AuthenticationService(inputValidationService, passwordHasher, store);

        var result = await authenticationService.LoginAsync("alice", "WrongPassword");

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAuthenticated, Is.False);
            Assert.That(result.Error, Is.EqualTo("Invalid username or password."));
        });
    }

    [Test]
    public async Task SqlInjectionStyleUsername_ShouldFailAuthentication()
    {
        var inputValidationService = new InputValidationService();
        var passwordHasher = new BCryptPasswordHasher();
        var storedHash = passwordHasher.HashPassword("CorrectP@ss123");

        var store = new InMemoryCredentialStore(new AuthUserRecord(1, "alice", storedHash, UserRole.User, true));
        var authenticationService = new AuthenticationService(inputValidationService, passwordHasher, store);

        var result = await authenticationService.LoginAsync("alice' OR '1'='1", "CorrectP@ss123");

        Assert.That(result.IsAuthenticated, Is.False);
    }

    [Test]
    public async Task ValidCredentials_ShouldReturnAuthenticatedUserWithRole()
    {
        var inputValidationService = new InputValidationService();
        var passwordHasher = new BCryptPasswordHasher();
        var storedHash = passwordHasher.HashPassword("StrongP@ss!2026");

        var store = new InMemoryCredentialStore(new AuthUserRecord(2, "admin1", storedHash, UserRole.Admin, true));
        var authenticationService = new AuthenticationService(inputValidationService, passwordHasher, store);

        var result = await authenticationService.LoginAsync("admin1", "StrongP@ss!2026");

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAuthenticated, Is.True);
            Assert.That(result.Username, Is.EqualTo("admin1"));
            Assert.That(result.Role, Is.EqualTo(UserRole.Admin));
        });
    }

    [Test]
    public void NonAdminUser_ShouldBeDeniedAdminDashboard()
    {
        var authorizationService = new AuthorizationService();

        var result = authorizationService.CanAccessAdminDashboard(UserRole.User);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAuthorized, Is.False);
            Assert.That(result.Error, Is.EqualTo("User is not authorized for this resource."));
        });
    }

    [Test]
    public void AdminUser_ShouldBeAllowedAdminDashboard()
    {
        var authorizationService = new AuthorizationService();

        var result = authorizationService.CanAccessAdminDashboard(UserRole.Admin);

        Assert.That(result.IsAuthorized, Is.True);
    }

    [Test]
    public void UndefinedRoleValue_ShouldBeDenied()
    {
        var authorizationService = new AuthorizationService();

        var result = authorizationService.CanAccessAdminDashboard((UserRole)999);

        Assert.That(result.IsAuthorized, Is.False);
    }

    [Test]
    public void MalformedPasswordHash_ShouldFailVerification()
    {
        var passwordHasher = new BCryptPasswordHasher();

        var result = passwordHasher.VerifyPassword("AnyPassword!1", "not-a-valid-bcrypt-hash");

        Assert.That(result, Is.False);
    }

    private sealed class InMemoryCredentialStore : IUserCredentialStore
    {
        private readonly Dictionary<string, AuthUserRecord> _users;

        public InMemoryCredentialStore(params AuthUserRecord[] users)
        {
            _users = users.ToDictionary(u => u.Username, StringComparer.OrdinalIgnoreCase);
        }

        public Task<AuthUserRecord?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            _users.TryGetValue(username, out var user);
            return Task.FromResult(user);
        }
    }
}