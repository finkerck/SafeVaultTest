using Microsoft.Data.Sqlite;
using SafeVault.Core.Security;

namespace SafeVault.Api.Data;

public enum CreateUserResult
{
    Success = 1,
    UsernameAlreadyExists = 2,
    Failed = 3
}

public sealed class SqliteUserStore : IUserCredentialStore
{
    private readonly string _connectionString;

    public SqliteUserStore(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task EnsureDatabaseAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL,
                Role TEXT NOT NULL,
                IsActive INTEGER NOT NULL DEFAULT 1
            );";

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<CreateUserResult> CreateUserAsync(
        string username,
        string email,
        string passwordHash,
        UserRole role,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO Users (Username, Email, PasswordHash, Role, IsActive)
            VALUES (@username, @email, @passwordHash, @role, 1);";

        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@email", email);
        command.Parameters.AddWithValue("@passwordHash", passwordHash);
        command.Parameters.AddWithValue("@role", role.ToString());

        try
        {
            var affected = await command.ExecuteNonQueryAsync(cancellationToken);
            return affected == 1 ? CreateUserResult.Success : CreateUserResult.Failed;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return CreateUserResult.UsernameAlreadyExists;
        }
    }

    public async Task<AuthUserRecord?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText = @"
            SELECT UserID, Username, PasswordHash, Role, IsActive
            FROM Users
            WHERE Username = @username
            LIMIT 1;";
        command.Parameters.AddWithValue("@username", username);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var userId = reader.GetInt32(reader.GetOrdinal("UserID"));
        var foundUsername = reader.GetString(reader.GetOrdinal("Username"));
        var passwordHash = reader.GetString(reader.GetOrdinal("PasswordHash"));
        var roleAsString = reader.GetString(reader.GetOrdinal("Role"));
        var isActive = reader.GetInt32(reader.GetOrdinal("IsActive")) == 1;

        if (!Enum.TryParse<UserRole>(roleAsString, true, out var role) || !Enum.IsDefined(role))
        {
            return null;
        }

        return new AuthUserRecord(userId, foundUsername, passwordHash, role, isActive);
    }
}