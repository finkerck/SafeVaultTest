using Microsoft.Data.Sqlite;
using SafeVault.Core.Data;
using SafeVault.Core.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    private InputValidationService _validationService = null!;

    [SetUp]
    public void Setup()
    {
        _validationService = new InputValidationService();
    }

    [Test]
    public async Task TestForSQLInjection()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var createTableCommand = connection.CreateCommand();
        createTableCommand.CommandText = @"
            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL
            );";
        await createTableCommand.ExecuteNonQueryAsync();

        var insertCommand = connection.CreateCommand();
        insertCommand.CommandText = "INSERT INTO Users (Username, Email) VALUES (@username, @email)";
        insertCommand.Parameters.AddWithValue("@username", "alice");
        insertCommand.Parameters.AddWithValue("@email", "alice@example.com");
        await insertCommand.ExecuteNonQueryAsync();

        var repository = new UserRepository(_validationService);
        var payload = "alice' OR '1'='1";
        var result = await repository.GetUserByUsernameAsync(connection, payload);

        Assert.That(result, Is.Null, "SQL injection payload should not match records when using parameterized queries.");
    }

    [Test]
    public void TestForXSS()
    {
        const string payload = "<script>alert('xss')</script>";
        var validationResult = _validationService.ValidateAndSanitizeUserInput(payload, "user@example.com");
        var encodedOutput = _validationService.EncodeForHtmlOutput(payload);

        Assert.Multiple(() =>
        {
            Assert.That(validationResult.SanitizedUsername, Does.Not.Contain("<"));
            Assert.That(validationResult.SanitizedUsername, Does.Not.Contain(">"));
            Assert.That(encodedOutput, Does.Not.Contain("<script>"));
            Assert.That(encodedOutput, Does.Contain("&lt;script&gt;"));
        });
    }

    [Test]
    public void TestForXssEventHandlerPayload()
    {
        const string payload = "<img src=x onerror=alert('xss')>";
        var encodedOutput = _validationService.EncodeForHtmlOutput(payload);

        Assert.Multiple(() =>
        {
            Assert.That(encodedOutput, Does.Not.Contain("<img"));
            Assert.That(encodedOutput, Does.Contain("&lt;img"));
            Assert.That(encodedOutput, Does.Contain("onerror"));
        });
    }
}