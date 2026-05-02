namespace SafeVault.Core.Security;

public sealed record AuthUserRecord(int UserId, string Username, string PasswordHash, UserRole Role, bool IsActive);