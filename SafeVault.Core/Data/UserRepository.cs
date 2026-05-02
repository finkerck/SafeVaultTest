using System.Data;
using System.Data.Common;
using SafeVault.Core.Security;

namespace SafeVault.Core.Data;

public sealed class UserRepository
{
    private readonly InputValidationService _inputValidationService;

    public UserRepository(InputValidationService inputValidationService)
    {
        _inputValidationService = inputValidationService;
    }

    public DbCommand BuildGetUserByUsernameCommand(DbConnection connection, string username)
    {
        ArgumentNullException.ThrowIfNull(connection);

        if (!_inputValidationService.TryNormalizeUsernameForLookup(username, out var normalizedUsername))
        {
            throw new ArgumentException("Username lookup value is invalid.", nameof(username));
        }

        var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username = @username";

        var parameter = command.CreateParameter();
        parameter.ParameterName = "@username";
        parameter.DbType = DbType.String;
        parameter.Value = normalizedUsername;
        command.Parameters.Add(parameter);

        return command;
    }

    public async Task<UserRecord?> GetUserByUsernameAsync(DbConnection connection, string username, CancellationToken cancellationToken = default)
    {
        if (!_inputValidationService.TryNormalizeUsernameForLookup(username, out _))
        {
            return null;
        }

        await using var command = BuildGetUserByUsernameCommand(connection, username);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new UserRecord(
            reader.GetInt32(reader.GetOrdinal("UserID")),
            reader.GetString(reader.GetOrdinal("Username")),
            reader.GetString(reader.GetOrdinal("Email"))
        );
    }
}

public sealed record UserRecord(int UserId, string Username, string Email);