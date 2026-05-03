using System.Text.RegularExpressions;

namespace SafeVault.Api.Security;

public static class PasswordPolicy
{
    private static readonly Regex Upper = new("[A-Z]", RegexOptions.Compiled);
    private static readonly Regex Lower = new("[a-z]", RegexOptions.Compiled);
    private static readonly Regex Digit = new("[0-9]", RegexOptions.Compiled);
    private static readonly Regex Special = new("[^a-zA-Z0-9]", RegexOptions.Compiled);

    public static bool IsStrongPassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            return false;
        }

        return Upper.IsMatch(password)
            && Lower.IsMatch(password)
            && Digit.IsMatch(password)
            && Special.IsMatch(password);
    }
}