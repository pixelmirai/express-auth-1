# Express Auth API Reference

This document describes the REST endpoints exposed by the Express Auth backend. All responses are JSON encoded and follow the envelope `{ "status": "success" | "error", ... }`.

## Base URL and Versioning

- **Base URL:** `http://localhost:3000`
- **Versioning:** The current API does not use URI-based versioning. Breaking changes are communicated out-of-band.

## Rate Limiting

Requests from a single IP address are limited to **100 requests per 15-minute window**. Exceeding this limit yields `429 Too Many Requests` with an error payload.【F:src/app.js†L15-L26】

## Authentication

Most endpoints require an **access token** issued during login. Supply it via the `Authorization: Bearer <access_token>` header. Access tokens are JWTs signed with the server secret and expire according to `ACCESS_TOKEN_TTL`. When an access token expires, use the refresh endpoint to obtain a fresh token pair.

User accounts transition through the following statuses:

- `pending_verification` – Default for new email registrations until the email is confirmed.
- `active` – User can access protected endpoints.
- `banned` – User is blocked from authenticating or using the API.【F:src/modules/auth/auth.service.js†L49-L150】【F:src/middleware/authMiddleware.js†L16-L28】

## Response Envelope

### Success

```json
{
  "status": "success",
  "data": { /* resource payload */ },
  "message": "Optional informational message"
}
```

### Errors

All errors share the following structure:

`json
{
  "status": "error",
  "message": "Human-readable description",
  "statusCode": 403,
  "code": "USER_BANNED",
  "details": [
    {
      "path": "body.email",
      "message": "Email must be a valid email"
    }
  ]
}
`

statusCode mirrors the HTTP status. code is a machine-friendly enum string (see docs/error-codes.md). details is present for validation failures only.
## Health

### `GET /health`

Returns the service status and uptime. Does not require authentication.【F:src/app.js†L28-L40】

**Response 200**

```json
{
  "status": "ok",
  "uptime": 123.456
}
```

## Authentication Endpoints

### `POST /auth/register`

Registers a new email/password user. Sends an email verification link as a background task.

- **Request Body**
  - `email` (string, required) – Must be unique and valid.
  - `password` (string, required) – Minimum 8 characters, including upper, lower, and numeric characters.
  - `name` (string, required) – 1-120 characters.【F:src/modules/auth/auth.validators.js†L11-L30】

**Response 201**

```json
{
  "status": "success",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "name": "User",
      "role": "user",
      "status": "pending_verification",
      "createdAt": "2024-01-01T00:00:00.000Z",
      "updatedAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

Existing accounts with the same email return `409 Conflict` with an error message.【F:src/modules/auth/auth.controller.js†L4-L13】【F:src/modules/auth/auth.service.js†L36-L75】

### `POST /auth/login`

Authenticates a verified, non-banned user via email and password.

- **Request Body**
  - `email` (string, required)
  - `password` (string, required)

**Response 200**

```json
{
  "status": "success",
  "data": {
    "user": { /* user fields */ },
    "accessToken": "jwt",
    "refreshToken": "opaque-refresh-token"
  }
}
```

Invalid credentials, pending verification, or banned status return `401`/`403` as appropriate.【F:src/modules/auth/auth.controller.js†L15-L24】【F:src/modules/auth/auth.service.js†L77-L124】

### `POST /auth/login/google`

Authenticates with a Google ID token.

- **Request Body**
  - `idToken` (string, required) – Google Sign-In ID token from the client.【F:src/modules/auth/auth.validators.js†L31-L36】

**Response 200** – Same payload shape as `/auth/login`.

Errors include `400` when the Google email is missing/unverified and `403` for banned users.【F:src/modules/auth/auth.controller.js†L26-L35】【F:src/modules/auth/auth.service.js†L126-L190】

### `POST /auth/refresh`

Exchanges a valid refresh token for a new access/refresh token pair. The previous refresh token is revoked.

- **Request Body**
  - `refreshToken` (string, required) – Previously issued refresh token.【F:src/modules/auth/auth.validators.js†L38-L43】

**Response 200** – Same payload shape as `/auth/login`.

Expired, revoked, or unknown refresh tokens return `401 Unauthorized`. Banned users trigger `403 Forbidden`.【F:src/modules/auth/auth.controller.js†L37-L44】【F:src/modules/auth/auth.service.js†L192-L231】

### `POST /auth/logout`

Revokes the provided refresh token. The endpoint is idempotent and always responds with success even if the token was absent.

- **Request Body**
  - `refreshToken` (string, required).【F:src/modules/auth/auth.validators.js†L45-L50】

**Response 200**

```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

### `POST /auth/verify-email`

Consumes an email verification token and activates the account.

- **Request Body**
  - `token` (string, required) – Token issued in the verification email.【F:src/modules/auth/auth.validators.js†L52-L57】

**Response 200** – Returns the updated `user` object.

Invalid or expired tokens yield `401 Unauthorized`. Banned users remain banned but the token is consumed.【F:src/modules/auth/auth.controller.js†L46-L53】【F:src/modules/auth/auth.service.js†L233-L269】

### `POST /auth/request-password-reset`

Starts the password reset flow. Always responds with success to avoid user enumeration.

- **Request Body**
  - `email` (string, required).【F:src/modules/auth/auth.validators.js†L59-L63】

**Response 200**

```json
{
  "status": "success",
  "message": "If the email exists, a reset link has been sent"
}
```

### `POST /auth/reset-password`

Sets a new password using a reset token. Revokes all refresh tokens for the user.

- **Request Body**
  - `token` (string, required)
  - `password` (string, required) – Must satisfy the password strength rules.【F:src/modules/auth/auth.validators.js†L65-L71】

**Response 200**

```json
{
  "status": "success",
  "message": "Password updated successfully"
}
```

Expired, used, or invalid tokens return `401 Unauthorized`.【F:src/modules/auth/auth.controller.js†L55-L64】【F:src/modules/auth/auth.service.js†L271-L313】

## User Endpoints

### `GET /users/me`

Returns the authenticated user's profile. Requires a valid access token.

**Response 200**

```json
{
  "status": "success",
  "data": {
    "user": { /* user fields */ }
  }
}
```

The user object omits `passwordHash` and includes identifiers and metadata from the database.【F:src/modules/users/users.controller.js†L1-L13】【F:src/modules/users/users.service.js†L1-L15】【F:prisma/schema.prisma†L10-L37】

## Admin Endpoints

All admin endpoints require a valid access token from a user whose `role` is `admin`. Non-admin callers receive `403 Forbidden`.【F:src/modules/admin/admin.routes.js†L1-L15】【F:src/middleware/roleMiddleware.js†L1-L11】

### `GET /admin/users`

Lists all users in descending creation order.

**Response 200**

```json
{
  "status": "success",
  "data": {
    "users": [ { /* user fields */ }, ... ]
  }
}
```

### `GET /admin/users/:id`

Fetches a specific user by ID. Returns `404 Not Found` if the user does not exist.【F:src/modules/admin/admin.controller.js†L13-L20】【F:src/modules/admin/admin.service.js†L19-L28】

### `PATCH /admin/users/:id/ban`

Marks a user as banned. Returns the updated user object. Missing users result in `404 Not Found`.【F:src/modules/admin/admin.controller.js†L22-L29】【F:src/modules/admin/admin.service.js†L30-L47】

### `PATCH /admin/users/:id/unban`

Marks a user as active. Returns the updated user object. Missing users result in `404 Not Found`.【F:src/modules/admin/admin.controller.js†L31-L38】【F:src/modules/admin/admin.service.js†L49-L66】

### `DELETE /admin/users/:id/delete`

Permanently removes a user and associated tokens/logs. Returns `204 No Content` on success or `404 Not Found` if the user does not exist.【F:src/modules/admin/admin.controller.js†L40-L47】【F:src/modules/admin/admin.service.js†L68-L94】

## Domain Objects

### User Object

Fields returned in user payloads:

| Field | Type | Description |
| --- | --- | --- |
| `id` | `string` | UUID identifier. |
| `email` | `string|null` | Email address if present. |
| `googleId` | `string|null` | Google account identifier. |
| `name` | `string|null` | Display name. |
| `avatarUrl` | `string|null` | Optional profile image URL. |
| `role` | `string` | `user` or `admin`. |
| `status` | `string` | `pending_verification`, `active`, or `banned`. |
| `createdAt` | `string` | ISO 8601 creation timestamp. |
| `updatedAt` | `string` | ISO 8601 last update timestamp. |

### Token Object

Token responses include:

- `accessToken` – JWT suitable for the `Authorization` header. Expires after `ACCESS_TOKEN_TTL` (e.g., `15m`).【F:src/utils/jwt.js†L4-L15】
- `refreshToken` – Opaque string usable once. Expires after `REFRESH_TOKEN_TTL` (e.g., `30d`) and is revoked on refresh or logout.【F:src/utils/tokens.js†L1-L35】

## Email Flows

- **Verification Emails:** Sent automatically after registration. Tokens expire after 24 hours.【F:src/modules/auth/auth.service.js†L20-L74】【F:src/modules/auth/auth.service.js†L205-L246】
- **Password Reset Emails:** Issued on request. Tokens expire after 1 hour and can be used once.【F:src/modules/auth/auth.service.js†L205-L313】

## Logging

Successful and failed login attempts are recorded with IP and user agent metadata for auditing.【F:src/modules/auth/auth.service.js†L22-L111】

## Appendix: Environment Variables

Relevant environment keys:

- `ACCESS_TOKEN_TTL` – Duration string for access token expiry (e.g., `15m`).
- `REFRESH_TOKEN_TTL` – Duration string for refresh token expiry (e.g., `30d`).
- `APP_URL` – Used in email templates for verification/reset links.

See `src/config/env.js` for the complete list and validation rules.【F:src/config/env.js†L1-L74】
