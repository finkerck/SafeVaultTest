using System.Net.Mail;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Core.Security;

public sealed class InputValidationService
{
    private static readonly Regex UsernameAllowedPattern = new("^[a-zA-Z0-9_.-]{3,50}$", RegexOptions.Compiled);

    public ValidationResult ValidateAndSanitizeUserInput(string? username, string? email)
    {
        var errors = new List<string>();

        var sanitizedUsername = SanitizeUsername(username);
        var sanitizedEmail = SanitizeEmail(email);

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || !UsernameAllowedPattern.IsMatch(sanitizedUsername))
        {
            errors.Add("Username must be 3-50 chars and contain only letters, numbers, underscore, dash, or dot.");
        }

        if (!IsValidEmail(sanitizedEmail))
        {
            errors.Add("Email is invalid.");
        }

        return new ValidationResult(errors.Count == 0, sanitizedUsername, sanitizedEmail, errors);
    }

    public string SanitizeLookupValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        normalized = Regex.Replace(normalized, "[\\x00-\\x1F\\x7F]", string.Empty);

        return normalized.Length > 100 ? normalized[..100] : normalized;
    }

    public bool TryNormalizeUsernameForLookup(string? username, out string normalizedUsername)
    {
        normalizedUsername = string.Empty;

        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        var cleaned = username.Trim();
        cleaned = Regex.Replace(cleaned, "[\\x00-\\x1F\\x7F]", string.Empty);

        if (!UsernameAllowedPattern.IsMatch(cleaned))
        {
            return false;
        }

        normalizedUsername = cleaned;
        return true;
    }

    public string EncodeForHtmlOutput(string? value)
    {
        return HtmlEncoder.Default.Encode(value ?? string.Empty);
    }

    private static string SanitizeUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return string.Empty;
        }

        var cleaned = username.Trim();
        cleaned = Regex.Replace(cleaned, "[\\x00-\\x1F\\x7F]", string.Empty);
        cleaned = Regex.Replace(cleaned, "[^a-zA-Z0-9_.-]", string.Empty);

        return cleaned.Length > 50 ? cleaned[..50] : cleaned;
    }

    private static string SanitizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return string.Empty;
        }

        var cleaned = email.Trim().ToLowerInvariant();
        cleaned = Regex.Replace(cleaned, "[\\x00-\\x1F\\x7F]", string.Empty);
        cleaned = cleaned.Replace("<", string.Empty).Replace(">", string.Empty).Replace("\"", string.Empty);

        return cleaned.Length > 100 ? cleaned[..100] : cleaned;
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            var mailAddress = new MailAddress(email);
            return string.Equals(mailAddress.Address, email, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}

public sealed record ValidationResult(bool IsValid, string SanitizedUsername, string SanitizedEmail, IReadOnlyList<string> Errors);