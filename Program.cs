using System.Net.Http.Headers;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Models;
using MatchmakingService.Services;

if (SigningKeyCli.TryRun(args, Console.Out, Console.Error)) return;

var builder = WebApplication.CreateBuilder(args);
var settings = builder.Configuration.GetSection(MatchmakingOptions.SectionName).Get<MatchmakingOptions>() ?? new();
var maxBodyBytes = Math.Clamp(settings.MaxRequestBodyBytes, 1024, 1024 * 1024);
var maxHeaderBytes = Math.Clamp(settings.MaxRequestHeadersTotalSize, 1024, 64 * 1024);

builder.WebHost.ConfigureKestrel(server =>
{
    server.Limits.MaxRequestBodySize = maxBodyBytes;
    server.Limits.MaxRequestHeadersTotalSize = maxHeaderBytes;
    server.Limits.MaxConcurrentConnections = Math.Max(1, settings.MaxConcurrentConnections);
    server.Limits.Http2.MaxStreamsPerConnection = 100;
});
builder.Services.AddOptions<MatchmakingOptions>().Bind(builder.Configuration.GetSection(MatchmakingOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.DatabasePath), "Matchmaking:DatabasePath is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.Tokens.Issuer) && !string.IsNullOrWhiteSpace(options.Tokens.ApiAudience), "Matchmaking:Tokens:Issuer and ApiAudience are required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.Tokens.AuthSigningKeyPem) || !string.IsNullOrWhiteSpace(options.Tokens.AuthSigningKeyPath), "Matchmaking:Tokens:AuthSigningKeyPath or AuthSigningKeyPem is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.Tokens.NatSigningKeyPem) || !string.IsNullOrWhiteSpace(options.Tokens.NatSigningKeyPath), "Matchmaking:Tokens:NatSigningKeyPath or NatSigningKeyPem is required.")
    .Validate(options => options.Tokens.AuthTokenLifetime > TimeSpan.Zero, "Matchmaking:Tokens:AuthTokenLifetime must be positive.")
    .Validate(options => options.Tokens.ClientTokenLifetime >= TimeSpan.FromSeconds(1) && options.Tokens.HostTokenLifetime >= TimeSpan.FromSeconds(1) && options.Tokens.OwnerTokenLifetime >= TimeSpan.FromSeconds(1), "Matchmaking:Tokens:ClientTokenLifetime, HostTokenLifetime and OwnerTokenLifetime must be at least one second.")
    .Validate(options => options.LoginProtection.MaxFailedAttempts > 0 && options.LoginProtection.FailureWindow > TimeSpan.Zero && options.LoginProtection.LockoutDuration > TimeSpan.Zero, "Matchmaking:LoginProtection values must be positive.")
    .ValidateOnStart();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<GameRegistry>();
builder.Services.AddSingleton<SigningKeys>();
builder.Services.AddSingleton<AuthTokenService>();
builder.Services.AddSingleton<NatTokenService>();
builder.Services.AddSingleton<AccountStore>();
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddSingleton<AccountService>();
builder.Services.AddHostedService<StartupInitializer>();
builder.Services.AddHostedService<GameCleanupService>();
builder.Services.AddRateLimiter(rateLimiter =>
{
    rateLimiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rateLimiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var limits = context.RequestServices.GetRequiredService<IOptions<MatchmakingOptions>>().Value.RateLimits;
        return PerIpPartition(context, limits.GlobalPermitLimit, limits.GlobalWindow);
    });
    rateLimiter.AddPolicy("create-game", context => PerIpPartition(context, GetRateLimits(context).CreatePermitLimit, GetRateLimits(context).CreateWindow));
    rateLimiter.AddPolicy("join-game", context => PerIpPartition(context, GetRateLimits(context).CreatePermitLimit, GetRateLimits(context).CreateWindow));
    rateLimiter.AddPolicy("list-games", context => PerIpPartition(context, GetRateLimits(context).ListPermitLimit, GetRateLimits(context).ListWindow));
    rateLimiter.AddPolicy("heartbeat", context => PerIpPartition(context, GetRateLimits(context).HeartbeatPermitLimit, GetRateLimits(context).HeartbeatWindow));
    rateLimiter.AddPolicy("delete-game", context => PerIpPartition(context, GetRateLimits(context).DeletePermitLimit, GetRateLimits(context).DeleteWindow));
    rateLimiter.AddPolicy("register", context => PerIpPartition(context, GetRateLimits(context).RegisterPermitLimit, GetRateLimits(context).RegisterWindow));
    rateLimiter.AddPolicy("login", context => PerIpPartition(context, GetRateLimits(context).LoginPermitLimit, GetRateLimits(context).LoginWindow));
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    try
    {
        await next(context);
    }
    catch (Exception exception) when (!context.Response.HasStarted)
    {
        try
        {
            context.RequestServices.GetRequiredService<ILogger<Program>>()
                .LogError("Unhandled request error for {Method} {Path} ({ExceptionType})",
                    context.Request.Method, context.Request.Path, exception.GetType().Name);
        }
        catch
        {
            // Logging failures must not expose the original exception to the client.
        }

        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new
        {
            type = "about:blank",
            title = "An unexpected error occurred.",
            status = StatusCodes.Status500InternalServerError
        });
    }
});

app.Use(async (context, next) =>
{
    var bodySizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (bodySizeFeature is { IsReadOnly: false }) bodySizeFeature.MaxRequestBodySize = maxBodyBytes;

    if (context.Request.ContentLength > maxBodyBytes)
    {
        context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        await context.Response.WriteAsJsonAsync(new { title = "Request body is too large.", status = 413 });
        return;
    }

    var isHeartbeat = HttpMethods.IsPost(context.Request.Method) && context.Request.Path.Value?.EndsWith("/heartbeat", StringComparison.OrdinalIgnoreCase) == true;
    if ((isHeartbeat || HttpMethods.IsDelete(context.Request.Method)) &&
        (context.Request.ContentLength is > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding")))
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { title = "This operation does not accept a request body.", status = 400 });
        return;
    }

    await next(context);
});

app.UseRouting();
app.UseRateLimiter();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

app.MapPost("/accounts/register", async (AccountCredentialsRequest? request, AccountService accounts, AuthTokenService authTokens, CancellationToken cancellationToken) =>
{
    if (request is null || !AccountService.TryNormalizeEmail(request.Email, out var email) || !AccountService.IsValidPassword(request.Password))
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["request"] = [$"A valid email address and a password of {AccountService.MinPasswordLength}-{AccountService.MaxPasswordLength} characters are required."]
        });
    }

    if (await accounts.RegisterAsync(email, request.Password!, cancellationToken) is not { } playerId)
        return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "An account with this email address already exists.");
    var authToken = authTokens.Create(playerId);
    return Results.Json(new AuthResponse(playerId, authToken.Token, authToken.ExpiresAtUtc), statusCode: StatusCodes.Status201Created);
}).RequireRateLimiting("register");

app.MapPost("/accounts/login", async (AccountCredentialsRequest? request, AccountService accounts, AuthTokenService authTokens, CancellationToken cancellationToken) =>
{
    if (request is null || !AccountService.TryNormalizeEmail(request.Email, out var email) ||
        string.IsNullOrEmpty(request.Password) || request.Password.Length > AccountService.MaxPasswordLength)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["request"] = ["A valid email address and password are required."]
        });
    }

    var result = await accounts.LoginAsync(email, request.Password, cancellationToken);
    if (result.Status == LoginStatus.LockedOut)
        return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "Too many failed sign-in attempts. Try again later.");
    // One generic failure for unknown emails and wrong passwords so account existence is not revealed.
    if (result.Status != LoginStatus.Success)
        return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "The email address or password is incorrect.");
    var authToken = authTokens.Create(result.PlayerId);
    return Results.Ok(new AuthResponse(result.PlayerId, authToken.Token, authToken.ExpiresAtUtc));
}).RequireRateLimiting("login");

// Owner (O) token: proves the account to a game server the player owns, for local games and before hosting one.
app.MapPost("/accounts/owner-token", async (HttpContext context, AuthTokenService authTokens, NatTokenService natTokens) =>
{
    if (await AuthenticatePlayerAsync(context, authTokens) is not { } playerId)
        return Unauthorized(context);
    return Results.Ok(new OwnerTokenResponse(natTokens.CreateOwnerToken(playerId)));
}).RequireRateLimiting("join-game");

app.MapPost("/games", async (CreateGameRequest? request, HttpContext context, GameRegistry games, AuthTokenService authTokens, NatTokenService natTokens) =>
{
    if (await AuthenticatePlayerAsync(context, authTokens) is not { } hostPlayerId)
        return Unauthorized(context);
    if (request is null || !CreateGameRequest.IsValid(request))
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["request"] = ["PlayerName, GameName, and a valid gameType are required; private games also require a secret."]
        });
    }

    try
    {
        var game = games.Register(hostPlayerId, request.PlayerName!.Trim(), request.GameName!.Trim(), request.GameType!, request.GameType == "private" ? request.Secret : null, context.Connection.RemoteIpAddress);
        var token = natTokens.CreateHostToken(game.Game.SessionId, hostPlayerId);
        return Results.Created($"/games/{game.Game.SessionId}", CreateGameResponse.From(game, token));
    }
    catch (SessionCapacityExceededException)
    {
        return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Session capacity is currently full.");
    }
}).RequireRateLimiting("create-game");

app.MapPost("/join", async (JoinGameRequest? request, HttpContext context, GameRegistry games, AuthTokenService authTokens, NatTokenService natTokens) =>
{
    if (await AuthenticatePlayerAsync(context, authTokens) is not { } playerId)
        return Unauthorized(context);
    if (request is null || !Guid.TryParse(request.Session, out var sessionId))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["session"] = ["A valid game session is required."] });
    var authorization = games.AuthorizeJoin(sessionId, request.Secret, out var game);
    if (authorization == JoinGameResult.NotFound) return Results.NotFound();
    if (authorization == JoinGameResult.InvalidCredential)
        return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "The private game credentials are invalid.");
    var token = natTokens.CreateClientToken(game!.SessionId, playerId);
    return Results.Ok(new JoinGameResponse(token));
}).RequireRateLimiting("join-game");
app.MapGet("/games", (GameRegistry games) =>
    Results.Ok(games.GetActiveGames().Select(HostedGameResponse.From)))
    .RequireRateLimiting("list-games");

app.MapPost("/games/{sessionId:guid}/heartbeat", (Guid sessionId, HttpContext context, GameRegistry games) =>
{
    if (!TryGetBearerCredential(context, settings.MaxAuthorizationHeaderBytes, out var ownerSecret))
        return Unauthorized(context);
    return ToOperationResult(games.Heartbeat(sessionId, ownerSecret));
}).RequireRateLimiting("heartbeat");

app.MapDelete("/games/{sessionId:guid}", (Guid sessionId, HttpContext context, GameRegistry games) =>
{
    if (!TryGetBearerCredential(context, settings.MaxAuthorizationHeaderBytes, out var ownerSecret))
        return Unauthorized(context);
    return ToOperationResult(games.Delete(sessionId, ownerSecret));
}).RequireRateLimiting("delete-game");

app.Run();

RateLimitPartition<string> PerIpPartition(HttpContext context, int permitLimit, TimeSpan window) =>
    RateLimitPartition.GetFixedWindowLimiter(
        GetClientKey(context),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, permitLimit),
            Window = window > TimeSpan.Zero ? window : TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });

static RateLimitOptions GetRateLimits(HttpContext context) =>
    context.RequestServices.GetRequiredService<IOptions<MatchmakingOptions>>().Value.RateLimits;

string GetClientKey(HttpContext context)
{
    var address = context.Connection.RemoteIpAddress;
    return address is null
        ? "unknown"
        : (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
}

// Create and join take an auth token; heartbeat and delete take the session owner secret. Both use Bearer.
async Task<Guid?> AuthenticatePlayerAsync(HttpContext context, AuthTokenService authTokens) =>
    TryGetBearerCredential(context, settings.MaxAuthorizationHeaderBytes, out var authToken)
        ? await authTokens.ValidateAsync(authToken)
        : null;

static bool TryGetBearerCredential(HttpContext context, int maxHeaderBytes, out string credential)
{
    credential = string.Empty;
    var value = context.Request.Headers.Authorization.ToString();
    if (value.Length == 0 || Encoding.UTF8.GetByteCount(value) > Math.Max(64, maxHeaderBytes)) return false;
    if (!AuthenticationHeaderValue.TryParse(value, out var authorization) ||
        !string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
        string.IsNullOrWhiteSpace(authorization.Parameter)) return false;
    credential = authorization.Parameter;
    return true;
}

static IResult Unauthorized(HttpContext context)
{
    context.Response.Headers.WWWAuthenticate = "Bearer";
    return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "A valid bearer credential is required.");
}

static IResult ToOperationResult(SessionOperationResult result) => result switch
{
    SessionOperationResult.Success => Results.NoContent(),
    SessionOperationResult.InvalidCredential => Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "The owner credential is invalid."),
    _ => Results.NotFound()
};

public partial class Program;
