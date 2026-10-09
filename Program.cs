using System.Net.Http.Headers;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;
using MatchmakingService.Models;
using MatchmakingService.Services;

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
builder.Services.Configure<MatchmakingOptions>(builder.Configuration.GetSection(MatchmakingOptions.SectionName));
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<GameRegistry>();
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
    rateLimiter.AddPolicy("list-games", context => PerIpPartition(context, GetRateLimits(context).ListPermitLimit, GetRateLimits(context).ListWindow));
    rateLimiter.AddPolicy("heartbeat", context => PerIpPartition(context, GetRateLimits(context).HeartbeatPermitLimit, GetRateLimits(context).HeartbeatWindow));
    rateLimiter.AddPolicy("delete-game", context => PerIpPartition(context, GetRateLimits(context).DeletePermitLimit, GetRateLimits(context).DeleteWindow));
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

app.MapPost("/games", (CreateGameRequest? request, HttpContext context, GameRegistry games) =>
{
    if (request is null || !CreateGameRequest.IsValid(request))
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["request"] = ["PlayerName and GameName are required and must be at most 64 and 100 characters respectively."]
        });
    }

    try
    {
        var game = games.Register(request.PlayerName!.Trim(), request.GameName!.Trim(), context.Connection.RemoteIpAddress);
        return Results.Created($"/games/{game.Game.SessionId}", CreateGameResponse.From(game));
    }
    catch (SessionCapacityExceededException)
    {
        return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Session capacity is currently full.");
    }
}).RequireRateLimiting("create-game");

app.MapGet("/games", (GameRegistry games) =>
    Results.Ok(games.GetActiveGames().Select(HostedGameResponse.From)))
    .RequireRateLimiting("list-games");

app.MapPost("/games/{sessionId:guid}/heartbeat", (Guid sessionId, HttpContext context, GameRegistry games) =>
{
    if (!TryGetOwnerSecret(context, settings.MaxAuthorizationHeaderBytes, out var ownerSecret))
        return Unauthorized(context);
    return ToOperationResult(games.Heartbeat(sessionId, ownerSecret));
}).RequireRateLimiting("heartbeat");

app.MapDelete("/games/{sessionId:guid}", (Guid sessionId, HttpContext context, GameRegistry games) =>
{
    if (!TryGetOwnerSecret(context, settings.MaxAuthorizationHeaderBytes, out var ownerSecret))
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

static bool TryGetOwnerSecret(HttpContext context, int maxHeaderBytes, out string ownerSecret)
{
    ownerSecret = string.Empty;
    var value = context.Request.Headers.Authorization.ToString();
    if (value.Length == 0 || Encoding.UTF8.GetByteCount(value) > Math.Max(64, maxHeaderBytes)) return false;
    if (!AuthenticationHeaderValue.TryParse(value, out var authorization) ||
        !string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
        string.IsNullOrWhiteSpace(authorization.Parameter)) return false;
    ownerSecret = authorization.Parameter;
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
