# MatchmakingService

A small ASP.NET Core HTTP service that keeps an in-memory list of hosted multiplayer games and expires hosts that stop sending heartbeats. It does not currently implement LiteNetLib, UDP NAT punching, or peer introduction. This prototype is single-process and its in-memory sessions are lost on restart.

## Prerequisites and run

- .NET 9 SDK

```powershell
dotnet build
dotnet run
```

By default the service listens on `http://localhost:5080`. Use HTTPS for non-local deployments. `/healthz` returns a minimal health response.

## HTTP API

### Create and retain a host credential

`POST /games` returns `201 Created` with a public `sessionId` and a one-time `ownerSecret`. Store the secret in the host process's secure secret storage; the service stores only its SHA-256 hash. Never put it in a URL, log, or public listing.

```powershell
$created = Invoke-RestMethod -Method Post -Uri http://localhost:5080/games `
  -ContentType 'application/json' `
  -Body '{"playerName":"Bob","gameName":"Survival Night"}'
$sessionId = $created.sessionId
$ownerSecret = $created.ownerSecret
```

### List public games

`GET /games` returns active public game data. It never returns credentials or internal hashes.

```powershell
Invoke-RestMethod -Method Get -Uri http://localhost:5080/games
```

### Heartbeat and stop hosting

Pass the owner secret in an `Authorization: Bearer` header. A successful heartbeat or deletion returns `204 No Content`. Missing credentials return `401`, incorrect credentials return `403`, and unknown or expired sessions return `404`.

```powershell
$headers = @{ Authorization = "Bearer $ownerSecret" }
Invoke-WebRequest -Method Post -Uri "http://localhost:5080/games/$sessionId/heartbeat" -Headers $headers
Invoke-WebRequest -Method Delete -Uri "http://localhost:5080/games/$sessionId" -Headers $headers
```

The secret is only returned by creation. If a host loses it, it must create a new session.

## Abuse controls and configuration

Settings live under `Matchmaking` in `appsettings.json` and can be overridden using standard .NET configuration environment variables such as `Matchmaking__MaxActiveSessions`.

- Session expiration defaults to 30 seconds; cleanup runs every 5 seconds.
- The service accepts at most 1,000 active sessions overall and 10 sessions per observed client IP.
- Kestrel allows at most 256 concurrent connections, limits request bodies to 16 KiB, and limits total request headers to 8 KiB by default. HTTP/2 connections allow at most 100 concurrent streams. Heartbeat and delete requests do not accept bodies.
- Fixed-window per-IP limits default to 5 creates/minute, 60 listings/minute, 30 heartbeats/minute, and 10 deletions/minute. A shared per-IP ceiling of 600 requests/minute also applies. Limits and windows are configurable.
- Capacity exhaustion returns `503`; rate-limited requests return `429`.

The service uses the normalized direct connection IP as its rate-limit partition key and does not trust `X-Forwarded-For`. Distinct observed IP addresses receive distinct partitions. This means limiter state grows with the number of distinct IPs, so protect the service at the network or proxy layer against high-cardinality traffic. Behind a reverse proxy, all clients may still share the proxy's limit and session quota. Configure forwarded headers only when you can explicitly restrict trusted proxies/networks. These application-level controls do not replace firewall, reverse-proxy, connection, or distributed denial-of-service protections. Rate limits and in-memory session state are prototype-scale controls, not a distributed deployment design.

Unexpected failures return a generic `500` response; internal exception messages and stack traces are not returned to clients. The registry serializes lifecycle changes so registration caps, owner checks, heartbeats, deletion, and cleanup are atomic with respect to one another.

## Tests

Run the xUnit unit and HTTP integration tests with:

```powershell
dotnet test .\MatchmakingService.Tests\MatchmakingService.Tests.csproj
```

The suite uses an injectable clock for expiration and cleanup tests. UDP functionality is not present, so malformed datagram, token, session-expiry, and peer-introduction authorization tests remain future work and no UDP security is claimed here.
