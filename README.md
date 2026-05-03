# SafeVaultTest

Activity 1, Activity 2, and Activity 3 implementation for SafeVault secure coding, access control, and security debugging.

## What is included

- Secure input validation and sanitization for username/email.
- HTML output encoding helper to reduce XSS risk.
- Parameterized SQL query implementation to mitigate SQL injection.
- BCrypt-based password hashing and verification for authentication.
- Role-based authorization (RBAC) with admin/user roles.
- Debugging hardening for lookup normalization, malformed hash handling, and strict role validation.
- NUnit security tests for SQL injection, XSS, authentication, and authorization scenarios.

## Project structure

- SafeVault.Core: security and data access logic.
- SafeVault.Tests: NUnit tests for attack simulation.
- webform.html: secure baseline form constraints.
- database.sql: users table schema.

## Run tests

```bash
dotnet test SafeVault.slnx
```

## Run the API

```bash
dotnet run --project SafeVault.Api --urls http://localhost:5057
```

## Quick manual API checks

1. Register a user

```powershell
Invoke-RestMethod -Uri "http://localhost:5057/register" -Method Post -ContentType "application/json" -Body '{"username":"user1","email":"user1@example.com","password":"StrongP@ss!1","role":"User"}'
```

2. Log in

```powershell
$login = Invoke-RestMethod -Uri "http://localhost:5057/login" -Method Post -ContentType "application/json" -Body '{"username":"user1","password":"StrongP@ss!1"}'
$token = $login.accessToken
```

3. Call an authenticated route

```powershell
Invoke-RestMethod -Uri "http://localhost:5057/me" -Headers @{ Authorization = "Bearer $token" } -Method Get
```

4. Admin-only route (requires Admin role token)

```powershell
Invoke-RestMethod -Uri "http://localhost:5057/admin/dashboard" -Headers @{ Authorization = "Bearer $token" } -Method Get
```

## Activity 3 Security Debug Summary

### Vulnerabilities identified

- Username lookup mutation risk: sanitization could alter malicious input into a different valid username shape instead of rejecting it.
- Password verification stability risk: malformed hash input could cause authentication flow instability.
- Role validation gap: undefined role values could be passed into authorization checks.

### Fixes applied

- Added strict username normalization with allowlist validation using `TryNormalizeUsernameForLookup`.
- Updated authentication and database lookup paths to reject invalid usernames early.
- Wrapped BCrypt verification in safe failure handling for malformed hash input.
- Hardened authorization to reject undefined role enum values before access checks.
- Added expanded XSS and SQLi-style regression tests.

### How Copilot assisted

- Scanned code paths for SQL query and output-handling weaknesses.
- Generated secure code patches for lookup validation, auth robustness, and RBAC hardening.
- Generated security regression tests simulating SQL injection and XSS payload attempts.
- Re-ran the full NUnit suite to confirm all fixes are effective.