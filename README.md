# MatchmakingService

A small ASP.NET Core HTTP service for player-hosted multiplayer games. It stores player accounts in SQLite, keeps an in-memory list of hosted games, expires hosts that stop sending heartbeats, and issues the tokens that hosts and clients present to the NAT introducer. It does not implement LiteNetLib, UDP NAT punching, or peer introduction itself. Hosted sessions are single-process and lost on restart; accounts persist.

## Prerequisites and run

- .NET 9 SDK

The service will not start without its two ES256 signing keys. Generate them once and keep them. Regenerating them invalidates every outstanding token and requires redistributing the NAT public key:

```powershell
dotnet build
dotnet run -- generate-signing-keys keys
dotnet run
```

By default the service listens on `http://localhost:5080`, reads keys from `keys/`, and stores accounts in `data/matchmaking.db`. Both paths are relative to the content root and are git-ignored. Use HTTPS for non-local deployments: passwords and bearer credentials travel in request bodies and headers. `/healthz` returns a minimal health response.

## Credentials at a glance

| Credential | Issued by | Sent to | Format | Default lifetime |
|---|---|---|---|---|
| Auth token | `/accounts/register`, `/accounts/login` | MM: `POST /games`, `POST /join` | ES256 JWT, audience `Tokens:ApiAudience` | 1 hour |
| Host token (role `H`) | `POST /games` | NAT introducer (host registration) | Compact 101-byte ES256 token | 24 hours |
| Client token (role `C`) | `POST /join` | NAT introducer (introduction request), then the host | Compact 101-byte ES256 token | 2 minutes |
| Owner token (role `O`) | `POST /accounts/owner-token` | The game server the player owns (never the NAT introducer) | Compact 101-byte ES256 token, empty session | 2 minutes |
| Owner secret | `POST /games` | MM: heartbeat and delete | Random 256-bit string | Session lifetime |

These are the only four MM-issued token types. There are no refresh tokens; when an auth token expires, the player logs in again. The owner secret is a per-session credential, not a token. Each credential is accepted only where the table says. An auth token is not an owner secret, and a host or client token is not an auth token.

## HTTP API

### Register and log in

`POST /accounts/register` takes `email` and `password`. It returns `201 Created` with `playerId`, `authToken`, and `expiresAtUtc`; successful registration counts as the first login.

- **Email:** trimmed, Unicode-NFC-normalized, and lower-cased before storage and lookup. A database `UNIQUE` constraint enforces one account per normalized email. Only simple `local@domain.tld` addresses are accepted, with no display names or quoted local parts, up to 254 characters.
- **Password:** 8–128 characters and not all whitespace. It is never trimmed.
- **Duplicate email:** returns `409`. Invalid input returns `400`.

`POST /accounts/login` takes the same body and returns `200 OK` with the same permanent `playerId` and a new `authToken`. A wrong password and an unknown email both return the same `401` response.

```powershell
$account = Invoke-RestMethod -Method Post -Uri http://localhost:5080/accounts/register `
  -ContentType 'application/json' -Body '{"email":"bob@example.com","password":"a long passphrase"}'
$auth = @{ Authorization = "Bearer $($account.authToken)" }
```

The player ID is a random GUID generated at registration and never changes. Email verification and password reset are not implemented.

### Create a public or private game

`POST /games` requires `Authorization: Bearer <authToken>`.

- **Request:** `playerName`, `gameName`, `gameType` (`public` or `private`), and an optional `secret`. Private games require a non-empty join secret.
- **Host identity:** always taken from the auth token. Fields such as `hostPlayerId` or `playerId` in the body are ignored.
- **Response:** `201 Created` with `sessionId`, `hostPlayerId`, the one-time `ownerSecret`, the host `token`, `playerName`, `gameName`, `gameType`, and `createdAtUtc`.
- **Storage:** the owner secret is stored only as a SHA-256 hash. The private join secret is held in memory for join checks and never appears in any token.

```powershell
$created = Invoke-RestMethod -Method Post -Uri http://localhost:5080/games -Headers $auth `
  -ContentType 'application/json' -Body '{"playerName":"Bob","gameName":"Survival Night","gameType":"public"}'
```

### List available games

`GET /games` is unauthenticated. It returns active public and private games with `sessionId`, `hostPlayerId`, `playerName`, `gameName`, `gameType`, and `createdAtUtc`. It never returns emails, join secrets, owner credentials, or tokens.

### Join a game

`POST /join` requires `Authorization: Bearer <authToken>` and takes `session` plus `secret` for private games. MM checks the private join secret before issuing anything. On success it returns `200 OK` with `token`, a client token bound to that session and the authenticated player. Errors:

- `401`: missing or invalid auth token.
- `403`: wrong private-game secret.
- `404`: unknown or expired session.

No token is issued on failure.

### Owner token

`POST /accounts/owner-token` requires `Authorization: Bearer <authToken>` and returns `{ "token": "..." }`. The token proves the account to a game server the player owns: the game server accepts it only if its player ID equals the server's configured owner. It has an all-zero session ID because it isn't tied to a game. The client fetches one right before connecting, because it expires after `Tokens:OwnerTokenLifetime` (default 2 minutes); an established connection is not affected by the expiry. The NAT introducer rejects owner tokens.

### Heartbeat and stop hosting

These endpoints are unchanged. Pass the owner secret as `Authorization: Bearer <ownerSecret>`. A successful heartbeat or deletion returns `204 No Content`. Missing credentials return `401`, incorrect credentials return `403`, and unknown or expired sessions return `404`. Auth tokens and host tokens are not accepted here.

```powershell
$headers = @{ Authorization = "Bearer $($created.ownerSecret)" }
Invoke-WebRequest -Method Post -Uri "http://localhost:5080/games/$($created.sessionId)/heartbeat" -Headers $headers
Invoke-WebRequest -Method Delete -Uri "http://localhost:5080/games/$($created.sessionId)" -Headers $headers
```

## Token formats

### Auth token (ES256 JWT)

A standard JWS compact token (`alg` `ES256`, `typ` `JWT`), signed with the auth key and validated by MM itself. Claims:

| Claim | Value |
|---|---|
| `sub` | permanent player ID (GUID, `D` format) |
| `iss` | `Tokens:Issuer` (default `matchmaking-service`) |
| `aud` | `Tokens:ApiAudience` (default `matchmaking-api`) |
| `iat`, `nbf` | issue time (Unix seconds) |
| `exp` | `iat` + `Tokens:AuthTokenLifetime` |
| `jti` | random unique ID |

MM checks the signature, algorithm (ES256 only), issuer, audience, `nbf`, and `exp`, with no clock skew. The token contains no email, password, or session data. It is about 380 characters long, so `MaxAuthorizationHeaderBytes` now defaults to 1024.

### Host and client tokens (compact ES256)

LiteNetLib (1.3.5) limits the NAT introduction token string to 256 characters, and an ES256 JWT with these claims does not fit. Host and client tokens therefore use a fixed binary layout signed with the separate NAT key:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | Session ID, RFC 4122 big-endian GUID bytes |
| 16 | 16 | Player ID, RFC 4122 big-endian GUID bytes |
| 32 | 1 | Role: ASCII `H` (0x48) host, `C` (0x43) client, `O` (0x4F) owner |
| 33 | 4 | Expiration: unsigned 32-bit big-endian Unix seconds |
| 37 | 64 | ES256 signature, raw IEEE P1363 `R \|\| S` |

- **Signing input:** exactly bytes 0–36 (`SessionId || PlayerId || Role || Expiration`), using ECDSA P-256 with SHA-256.
- **Encoding:** 101 bytes as unpadded Base64URL, giving **135 characters**.
- **GUID byte order:** the RFC 4122 / network order, i.e. the hex digits of the `D` string in order. In .NET that is `Guid.TryWriteBytes(span, bigEndian: true, …)` and `new Guid(span, bigEndian: true)`. It is not the default `Guid.ToByteArray()` order.
- **Expiration range:** 1 to 4294967295, so the latest representable expiry is 2106-02-07 06:28:15 UTC. MM refuses to issue a token whose expiry would exceed that.
- **No issuer or audience fields:** the format is identified by its context. It must only be accepted as an MM-issued NAT token in the NAT introduction protocol, never as an MM API credential. MM rejects these tokens as auth tokens because they are not JWTs and are signed with a different key.

The private join secret, owner secret, email, password, and auth token never appear in either token.

## Signing keys

MM holds two ECDSA P-256 private keys:

- **Auth key** (`Tokens:AuthSigningKeyPath` or `Tokens:AuthSigningKeyPem`) signs auth tokens and is only ever needed by MM.
- **NAT key** (`Tokens:NatSigningKeyPath` or `Tokens:NatSigningKeyPem`) signs host and client tokens. The NAT introducer will need its **public** key.

Keeping them separate means the introducer never holds anything that could verify auth tokens, and the two keys can be rotated independently. MM refuses to start if either key is missing, unreadable, not a P-256 private key, or if both are the same key. Inline `*Pem` values take precedence over paths and suit environment variables or secret stores, for example `Matchmaking__Tokens__NatSigningKeyPem`.

```powershell
dotnet run -- generate-signing-keys keys                     # writes mm-auth-signing.pem, mm-nat-signing.pem and .pub.pem files; never overwrites
dotnet run -- export-public-key keys\mm-nat-signing.pem      # prints the NAT public key PEM for the introducer
```

Never commit or distribute the private `.pem` files. On Linux they are created with mode `600`. On Windows, restrict the file ACLs yourself. Only `mm-nat-signing.pub.pem` should be given to the NAT introducer.

## Configuration

Settings live under `Matchmaking` in `appsettings.json` and can be overridden with standard .NET configuration environment variables such as `Matchmaking__Tokens__HostTokenLifetime`.

| Setting | Default | Notes |
|---|---|---|
| `DatabasePath` | `data/matchmaking.db` | SQLite file (WAL mode); schema created/migrated at startup via `PRAGMA user_version` |
| `Tokens:Issuer` | `matchmaking-service` | auth token `iss` |
| `Tokens:ApiAudience` | `matchmaking-api` | auth token `aud` |
| `Tokens:AuthTokenLifetime` | `01:00:00` | |
| `Tokens:ClientTokenLifetime` | `00:02:00` | long enough for the client's introduction retries |
| `Tokens:HostTokenLifetime` | `1.00:00:00` | see below |
| `LoginProtection:MaxFailedAttempts` / `FailureWindow` / `LockoutDuration` | 5 / 15 min / 15 min | per-email lockout |
| `RateLimits:RegisterPermitLimit` / `LoginPermitLimit` | 5 / 10 per minute | per IP |

The host token default is 24 hours because the game host re-sends the same host token to the introducer on a fixed interval for the whole session, and MM has no endpoint to refresh it. A host session that runs longer than `HostTokenLifetime` will be rejected by an introducer that checks expiry, and the host must register a new session. Keep this value longer than your expected session length.

## Abuse controls

- **Sessions:** expire after 30 seconds without a heartbeat; cleanup runs every 5 seconds.
- **Capacity:** at most 1,000 active sessions overall and 10 per observed client IP.
- **Kestrel limits:** at most 256 concurrent connections, 16 KiB request bodies, and 8 KiB of request headers by default. HTTP/2 connections allow at most 100 concurrent streams. Heartbeat and delete requests do not accept bodies.
- **Per-IP rate limits** (fixed window, configurable):
  - creates and joins share one limit: 5/minute;
  - listings: 60/minute;
  - heartbeats: 30/minute;
  - deletions: 10/minute;
  - registrations: 5/minute;
  - logins: 10/minute;
  - shared ceiling across all requests: 600/minute.
- **Login lockout:** each login attempt counts against the normalized email before the password is checked. Five attempts without a success lock that email for 15 minutes, returning `429`. Unknown emails are tracked the same way, so a lockout does not reveal whether an account exists. A successful login clears the count. One trade-off: someone who knows a player's email can deliberately trigger that player's lockout. Unknown-email logins are also checked against a dummy password hash so they take about as long as a wrong password.
- **Passwords:** hashed with ASP.NET Core Identity's `PasswordHasher` (PBKDF2-HMAC-SHA512, random salt, versioned format). Plaintext passwords and token copies are never stored.
- **Error responses:** capacity exhaustion returns `503` and rate-limited requests return `429`.

The service uses the normalized direct connection IP as its rate-limit partition key and does not trust `X-Forwarded-For`. Distinct observed IP addresses receive distinct partitions, so limiter state grows with the number of distinct IPs. Protect the service at the network or proxy layer against high-cardinality traffic. Behind a reverse proxy, all clients may share the proxy's limit and session quota. Configure forwarded headers only when you can explicitly restrict trusted proxies or networks. These application-level controls do not replace firewall, reverse-proxy, connection, or distributed denial-of-service protections. Rate limits, the login lockout, and in-memory sessions are prototype-scale, single-instance controls.

Unexpected failures return a generic `500` response; internal exception messages and stack traces are not returned to clients. Passwords, emails, tokens, owner secrets, join secrets, and key material are not logged. The registry serializes lifecycle changes so registration caps, owner checks, heartbeats, deletion, and cleanup are atomic with respect to one another.

## Compatibility and required follow-up work

These changes break the previous integration on purpose. The other components need updating before they work with this version of MM:

- **NAT introducer:** done in the `NAT test` repository. The introducer verifies H and C tokens with `mm-nat-signing.pub.pem`. It checks:
  1. canonical 101-byte Base64URL;
  2. the P1363 signature over bytes 0–36;
  3. expiry;
  4. the role selects the operation (`H` registers, `C` asks for an introduction);
  5. the token's session.

  It binds each host registration to the host's player ID and hands both peers its own signed introduction token. Its end-to-end tests run against this service's real tokens. Verification uses BouncyCastle, because Unity's Mono does not implement `System.Security.Cryptography.ECDsa`. See that repository's README.
- **Game host (Unity server / NAT test server):**
  - log in or register first;
  - send `Authorization: Bearer <authToken>` on `POST /games`;
  - keep using `ownerSecret` for heartbeat and delete;
  - pass the returned `token` (135 characters, fits LiteNetLib) to the introducer as before;
  - authorize connecting players by verifying their client token, instead of checking the `"public"` key or the private secret.
- **Game client (Unity client / NAT test client):**
  - log in or register first;
  - send `Authorization: Bearer <authToken>` on `POST /join`;
  - pass the returned `token` to the introducer as before, and send it again as connection data to the host. Join responses keep the same shape; `403` still means a wrong private secret, and `401` now means a missing or expired auth token.

  The NAT test host and client implement both changes and are tested end to end, including under Unity's Mono runtime. The Unity projects are not updated yet.
- **Listings:** gain a `hostPlayerId` field. Existing fields are unchanged.

Offline play does not touch MM and needs no account.

## Tests

Run the xUnit unit and HTTP integration tests with:

```powershell
dotnet test .\MatchmakingService.Tests\MatchmakingService.Tests.csproj
```

Tests generate throwaway signing keys in memory and use a temporary SQLite file per test host. They cover:

- accounts, login lockout, and per-IP rate limits;
- auth token claims and rejection (expiry, wrong key, issuer, audience, unsigned tokens, cross-type tokens);
- compact token layout, GUID byte order, signature coverage, role substitution, expiry range, and the 256-character limit;
- key loading and the key CLI;
- secret exposure in logs and responses;
- the existing session lifecycle.

This service has no UDP code. NAT-side verification and peer-introduction authorization are tested in the `NAT test` repository, whose end-to-end tests build and run this service.
