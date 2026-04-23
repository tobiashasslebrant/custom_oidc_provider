# Project Context: .NET OIDC Provider Implementation

This project is a custom OpenID Connect (OIDC) Provider built using .NET 8.0+. The goal is to provide a lightweight, standards-compliant identity layer without using heavy third-party "black-box" frameworks unless explicitly asked.

## Core Tech Stack
- Framework: ASP.NET Core Minimal APIs or Controllers.
- Security: `Microsoft.AspNetCore.Authentication.JwtBearer`, `System.IdentityModel.Tokens.Jwt`.
- Persistence: Entity Framework Core (PostgreSQL).

## OIDC Implementation Rules
1. **Compliance**: Strictly follow the OpenID Connect Core 1.0 and RFC 6749 (OAuth 2.0) specifications.
2. **Endpoints**:
   - Discovery: `/.well-known/openid-configuration`
   - JWKS: `/.well-known/jwks.json`
   - Authorization: `/connect/authorize`
   - Token: `/connect/token`
   - UserInfo: `/connect/userinfo`
3. **Security Defaults**:
   - Always use `RS256` for signing JWTs.
   - Force `HTTPS` for all redirect URIs.
   - Use `SameSite=None` and `Secure` for any session cookies used during the auth flow.
   - PKCE (Proof Key for Code Exchange) is mandatory for all code flows.

## Coding Standards
- **Asynchronous**: Use `async/await` for all I/O and DB operations.
- **Dependency Injection**: Always use constructor injection for services and DB contexts.
- **Result Pattern**: Prefer returning a `Result<T>` or specific DTOs instead of throwing exceptions for logic errors (e.g., "invalid_grant").
- **Logging**: Use `ILogger` to log protocol errors (e.g., "Invalid client secret attempted for client {ClientId}").

## Domain Logic
- **Claims**: Support standard claims (`sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`).
- **Scopes**: Support `openid`, `profile`, and `email` by default.
- **Validation**:
   - Validate `redirect_uri` against a pre-registered whitelist.
   - Validate `client_id` and `client_secret` using cryptographic hashing (do not store secrets in plain text).

## Formatting
- Use C# 12 features (Primary constructors, collection expressions).
- Keep methods small and focused on one part of the OIDC handshake.
