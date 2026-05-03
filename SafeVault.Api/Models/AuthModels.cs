namespace SafeVault.Api.Models;

public sealed record RegisterRequest(string? Username, string? Email, string? Password, string? Role);

public sealed record LoginRequest(string? Username, string? Password);

public sealed record LoginResponse(string AccessToken, string Username, string Role);

public sealed record UserListItem(int UserId, string Username, string Email, string Role, bool IsActive);