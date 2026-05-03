using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Data;
using SafeVault.Api.Models;
using SafeVault.Api.Security;
using SafeVault.Core.Security;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

var connectionString = builder.Configuration.GetConnectionString("SafeVaultDb")
    ?? "Data Source=safevault.db";
var jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("JWT signing key is not configured.");

builder.Services.AddSingleton(new SqliteUserStore(connectionString));
builder.Services.AddSingleton<IUserCredentialStore>(sp => sp.GetRequiredService<SqliteUserStore>());
builder.Services.AddSingleton<InputValidationService>();
builder.Services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddSingleton<AuthenticationService>();
builder.Services.AddSingleton(new JwtTokenService(jwtKey));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(UserRole.Admin.ToString()));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

await app.Services.GetRequiredService<SqliteUserStore>().EnsureDatabaseAsync();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (
    RegisterRequest request,
    SqliteUserStore userStore,
    InputValidationService inputValidationService,
    IPasswordHasher passwordHasher) =>
{
    var validation = inputValidationService.ValidateAndSanitizeUserInput(request.Username, request.Email);
    if (!validation.IsValid)
    {
        return Results.BadRequest(new { errors = validation.Errors });
    }

    if (!PasswordPolicy.IsStrongPassword(request.Password))
    {
        return Results.BadRequest(new
        {
            errors = new[]
            {
                "Password must be at least 8 characters and include upper, lower, number, and special character."
            }
        });
    }

    if (!TryParseRole(request.Role, out var role))
    {
        return Results.BadRequest(new { errors = new[] { "Role must be User or Admin." } });
    }

    var passwordHash = passwordHasher.HashPassword(request.Password!);
    var createResult = await userStore.CreateUserAsync(
        validation.SanitizedUsername,
        validation.SanitizedEmail,
        passwordHash,
        role);

    return createResult switch
    {
        CreateUserResult.Success => Results.Created($"/users/{validation.SanitizedUsername}", new
        {
            username = validation.SanitizedUsername,
            role = role.ToString()
        }),
        CreateUserResult.UsernameAlreadyExists => Results.Conflict(new
        {
            errors = new[] { "Username already exists." }
        }),
        _ => Results.StatusCode(StatusCodes.Status500InternalServerError)
    };
})
.AllowAnonymous();

app.MapPost("/login", async (
    LoginRequest request,
    AuthenticationService authenticationService,
    JwtTokenService tokenService) =>
{
    var loginResult = await authenticationService.LoginAsync(request.Username, request.Password);
    if (!loginResult.IsAuthenticated || loginResult.Role is null || loginResult.UserId is null || loginResult.Username is null)
    {
        return Results.Unauthorized();
    }

    var token = tokenService.CreateToken(loginResult.UserId.Value, loginResult.Username, loginResult.Role.Value);
    return Results.Ok(new LoginResponse(token, loginResult.Username, loginResult.Role.Value.ToString()));
})
.AllowAnonymous();

app.MapGet("/admin/dashboard", () =>
{
    return Results.Ok(new { message = "Admin dashboard: sensitive admin tools visible." });
})
.RequireAuthorization("AdminOnly");

app.MapGet("/admin/users", async (SqliteUserStore userStore) =>
{
    var users = await userStore.ListUsersAsync();
    return Results.Ok(users);
})
.RequireAuthorization("AdminOnly");

app.MapGet("/me", (System.Security.Claims.ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        username = user.Identity?.Name,
        role = user.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role)?.Value
    });
})
.RequireAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

app.Run();

static bool TryParseRole(string? requestedRole, out UserRole role)
{
    role = UserRole.User;

    if (string.IsNullOrWhiteSpace(requestedRole))
    {
        return true;
    }

    return Enum.TryParse<UserRole>(requestedRole, true, out role) && Enum.IsDefined(role);
}
