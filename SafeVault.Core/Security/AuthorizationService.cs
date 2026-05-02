namespace SafeVault.Core.Security;

public sealed class AuthorizationService
{
    public AuthorizationResult AuthorizeAccess(UserRole userRole, UserRole requiredRole)
    {
        if (!Enum.IsDefined(userRole) || !Enum.IsDefined(requiredRole))
        {
            return AuthorizationResult.Denied("User is not authorized for this resource.");
        }

        if (userRole < requiredRole)
        {
            return AuthorizationResult.Denied("User is not authorized for this resource.");
        }

        return AuthorizationResult.Allowed();
    }

    public AuthorizationResult CanAccessAdminDashboard(UserRole userRole)
    {
        return AuthorizeAccess(userRole, UserRole.Admin);
    }
}

public sealed record AuthorizationResult(bool IsAuthorized, string? Error)
{
    public static AuthorizationResult Allowed() => new(true, null);

    public static AuthorizationResult Denied(string error) => new(false, error);
}