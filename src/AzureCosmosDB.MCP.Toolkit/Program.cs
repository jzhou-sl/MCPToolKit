// Program.cs
using ModelContextProtocol.Server;
using System.ComponentModel;
using Microsoft.Azure.Cosmos;
using System.Text.Json;
using Azure.Identity;
using System.Text.RegularExpressions;
using Azure.AI.OpenAI;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using AzureCosmosDB.MCP.Toolkit.Services;

var builder = WebApplication.CreateBuilder(args);

// Add controllers
builder.Services.AddControllers();

// Disable default claim mapping for cleaner token handling
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// Azure Functions runs this server as a custom handler (host.json) and tells it which port to serve on in
// FUNCTIONS_CUSTOMHANDLER_PORT; in a container or locally it serves 8080.
builder.WebHost.ConfigureKestrel(options =>
{
    var port = int.TryParse(Environment.GetEnvironmentVariable("FUNCTIONS_CUSTOMHANDLER_PORT"), out var p) ? p : 8080;
    options.ListenAnyIP(port);
});

// Get Azure AD configuration from appsettings
var azureAd = builder.Configuration.GetSection("AzureAd");
var tenantId = azureAd["TenantId"];
var clientId = azureAd["ClientId"];
var audienceConfig = azureAd["Audience"];

// Check if authentication should be bypassed for development
var devBypassAuth = Environment.GetEnvironmentVariable("DEV_BYPASS_AUTH") == "true" || 
                   builder.Configuration.GetValue<bool>("DevelopmentMode:BypassAuthentication");
var isDevelopment = builder.Environment.IsDevelopment();

if (!devBypassAuth && !string.IsNullOrEmpty(tenantId) && !string.IsNullOrEmpty(clientId))
{
    // Build list of valid audiences
    var validAudiences = new List<string> { clientId, $"api://{clientId}" };
    
    // Add audiences from configuration (supports comma-separated values)
    if (!string.IsNullOrEmpty(audienceConfig))
    {
        var configuredAudiences = audienceConfig.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var aud in configuredAudiences)
        {
            if (!validAudiences.Contains(aud))
            {
                validAudiences.Add(aud);
            }
        }
    }
    
    // Add JWT Bearer authentication only if configuration is available. MCP clients such as Claude find how to sign
    // in from /.well-known/oauth-authorization-server (mapped below) and the scope in each 401.
    // The default scheme ("Artifact", below) forwards Entra tokens here.
    builder.Services
        .AddAuthentication()
        .AddJwtBearer(options =>
        {
            options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";

            options.TokenValidationParameters = new TokenValidationParameters
            {
                // Multi-tenant support: Accept tokens from any Azure AD tenant
                ValidateIssuer = true,
                // Accept both v1.0 and v2.0 tokens from any tenant
                IssuerValidator = (issuer, securityToken, validationParameters) =>
                {
                    // Accept issuers matching either pattern from any tenant:
                    // v2.0: https://login.microsoftonline.com/{tenantId}/v2.0
                    // v1.0: https://sts.windows.net/{tenantId}/
                    if (issuer.StartsWith("https://login.microsoftonline.com/") && issuer.EndsWith("/v2.0") ||
                        issuer.StartsWith("https://sts.windows.net/") && issuer.EndsWith("/"))
                    {
                        return issuer;
                    }
                    throw new SecurityTokenInvalidIssuerException($"Invalid issuer: {issuer}");
                },

                ValidateAudience = true,
                ValidAudiences = validAudiences,

                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(2),
                RoleClaimType = "roles",
            };

            options.MapInboundClaims = false;
            options.RefreshOnIssuerKeyNotFound = true;

            // Add detailed logging for authentication events
            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    
                    // Check query parameter first (Container Apps doesn't strip this)
                    if (string.IsNullOrEmpty(context.Token))
                    {
                        var accessToken = context.Request.Query["access_token"].FirstOrDefault();
                        if (!string.IsNullOrEmpty(accessToken))
                        {
                            context.Token = accessToken;
                            logger.LogInformation("Token retrieved from query parameter");
                        }
                    }
                    
                    // Workaround: Azure Container Apps ingress may strip Authorization header
                    // Check for custom header as fallback
                    if (string.IsNullOrEmpty(context.Token))
                    {
                        // Try multiple header names since Azure Container Apps may strip some
                        if (context.Request.Headers.TryGetValue("X-MS-TOKEN-AAD-ACCESS-TOKEN", out var tokenValue))
                        {
                            context.Token = tokenValue;
                            logger.LogInformation("Token retrieved from X-MS-TOKEN-AAD-ACCESS-TOKEN header");
                        }
                        else if (context.Request.Headers.TryGetValue("X-Access-Token", out var customTokenValue))
                        {
                            context.Token = customTokenValue;
                            logger.LogInformation("Token retrieved from X-Access-Token header");
                        }
                        else if (context.Request.Headers.TryGetValue("X-Auth-Token", out var authTokenValue))
                        {
                            context.Token = authTokenValue;
                            logger.LogInformation("Token retrieved from X-Auth-Token header");
                        }
                    }
                    
                    var hasAuth = context.Request.Headers.ContainsKey("Authorization");
                    var hasCustom = context.Request.Headers.ContainsKey("X-MS-TOKEN-AAD-ACCESS-TOKEN");
                    var hasQuery = !string.IsNullOrEmpty(context.Request.Query["access_token"].FirstOrDefault());
                    logger.LogInformation("Message received. Has Authorization header: {HasAuth}, Has X-MS-TOKEN-AAD-ACCESS-TOKEN: {HasCustom}, Has Query Token: {HasQuery}", hasAuth, hasCustom, hasQuery);
                    
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    logger.LogError("Authentication failed: {Error}", context.Exception.Message);
                    logger.LogError("Exception details: {Details}", context.Exception.ToString());
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    logger.LogInformation("Token validated successfully for user: {User}", context.Principal?.Identity?.Name ?? "Unknown");
                    return Task.CompletedTask;
                },
                OnChallenge = context =>
                {
                    // Never log request headers here: they include the caller's bearer token.
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    logger.LogWarning("Authentication challenge: {Error}, {ErrorDescription}", context.Error, context.ErrorDescription);

                    // Tell MCP clients which scope to ask Entra for. No resource_metadata: with it, clients send an
                    // RFC 8707 resource parameter, which Entra rejects (AADSTS9010010) for a <client ID>/.default scope.
                    context.HandleResponse();
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    var parameters = new List<string> { $"scope=\"{clientId}/.default offline_access\"" };
                    if (!string.IsNullOrEmpty(context.Error)) parameters.Add($"error=\"{context.Error}\"");
                    context.Response.Headers.WWWAuthenticate = "Bearer " + string.Join(", ", parameters);
                    return Task.CompletedTask;
                }
            };
        });

    // Add authorization with policy for MCP Tool Executor role
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("McpToolExecutor", p => p.RequireRole("Mcp.Tool.Executor"));

        options.DefaultPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
    });
}
else
{
    // Development mode - bypass authentication
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("McpToolExecutor", policy => policy.RequireAssertion(_ => true));
        options.DefaultPolicy = new AuthorizationPolicyBuilder()
            .RequireAssertion(_ => true)
            .Build();
    });
}

// People using the artifact's page sign in with its Static Web App, whose "ticket" managed function gives the page a
// short-lived ticket signed with TICKET_SECRET (Artifact/TicketAuthentication.cs). The page sends it as a bearer
// token, like Claude's Entra tokens; tickets have two dot-separated parts and JWTs three, which picks the scheme.
// Tickets work without the MCP server API registration above, which only Claude needs.
//
// With COSMOS_TOKEN_PASSTHROUGH on (test only), Claude Code can instead send the person's own Cosmos DB token from the
// Azure CLI as its bearer token, with no app registration (docs/cosmos-token-passthrough.md, "Claude Code"). That
// token then says who is calling, so the "CosmosToken" scheme verifies it against Entra: signature, this tenant as
// issuer, a Cosmos DB audience, lifetime. A bearer goes there when its aud is Cosmos DB.
var jwtConfigured = !devBypassAuth && !string.IsNullOrEmpty(tenantId) && !string.IsNullOrEmpty(clientId);
var cosmosBearerConfigured = !devBypassAuth && !string.IsNullOrEmpty(tenantId)
    && AzureCosmosDB.MCP.Toolkit.Artifact.CosmosTokenPassthrough.Enabled;
var authentication = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = "Artifact";
        options.DefaultChallengeScheme = "Artifact";
    })
    .AddScheme<AuthenticationSchemeOptions, AzureCosmosDB.MCP.Toolkit.Artifact.TicketAuthenticationHandler>(
        AzureCosmosDB.MCP.Toolkit.Artifact.TicketAuthenticationHandler.SchemeName, null)
    .AddPolicyScheme("Artifact", "Ticket, Cosmos DB token or Entra token", options =>
        options.ForwardDefaultSelector = context =>
            AzureCosmosDB.MCP.Toolkit.Artifact.TicketAuthenticationHandler.HasTicket(context.Request)
                ? AzureCosmosDB.MCP.Toolkit.Artifact.TicketAuthenticationHandler.SchemeName
            : cosmosBearerConfigured && AzureCosmosDB.MCP.Toolkit.Artifact.CosmosTokenPassthrough.IsCosmosBearer(context.Request)
                ? AzureCosmosDB.MCP.Toolkit.Artifact.CosmosTokenPassthrough.SchemeName
            : jwtConfigured
                ? JwtBearerDefaults.AuthenticationScheme
                : AzureCosmosDB.MCP.Toolkit.Artifact.TicketAuthenticationHandler.SchemeName);
if (cosmosBearerConfigured)
{
    authentication.AddJwtBearer(AzureCosmosDB.MCP.Toolkit.Artifact.CosmosTokenPassthrough.SchemeName, options =>
    {
        options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0"; // signing keys; v1 tokens share them
        options.MapInboundClaims = false;
        options.RefreshOnIssuerKeyNotFound = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            // Azure CLI tokens asked for with --resource are v1 (sts.windows.net); allow v2 too. This tenant only.
            ValidIssuers = [$"https://sts.windows.net/{tenantId}/", $"https://login.microsoftonline.com/{tenantId}/v2.0"],
            ValidateAudience = true,
            // Cosmos DB's audiences, as CosmosTokenPassthrough accepts them. The aud can be the account endpoint with ":443" and a trailing "/"; compare it as Audiences() lists it.
            AudienceValidator = (audiences, _, _) =>
            {
                var valid = AzureCosmosDB.MCP.Toolkit.Artifact.CosmosTokenPassthrough.Audiences();
                return audiences.Any(a => valid.Contains(a.Trim().TrimEnd('/').Replace(":443", "", StringComparison.Ordinal)));
            },
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "upn",
            // The identity's AuthenticationType defaults to "AuthenticationTypes.Federation"; name it after this
            // scheme so CosmosTokenPassthrough.VerifiedBearer recognises it and uses the bearer as the Cosmos DB token.
            AuthenticationType = AzureCosmosDB.MCP.Toolkit.Artifact.CosmosTokenPassthrough.SchemeName,
        };
    });
}

// Add HTTP context accessor for authentication
builder.Services.AddHttpContextAccessor();

// Add CORS for external MCP access
builder.Services.AddCors(options =>
{
    options.AddPolicy("MCPPolicy", policy =>
    {
        // CORS_ALLOWED_ORIGINS (comma-separated) limits browsers to the artifact's own site; unset, any origin.
        var origins = (Environment.GetEnvironmentVariable("CORS_ALLOWED_ORIGINS") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (origins.Length > 0) policy.WithOrigins(origins);
        else policy.AllowAnyOrigin();
        policy.AllowAnyMethod()
              .AllowAnyHeader()
              .WithExposedHeaders("Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Mcp-Session-Id");
    });
});

// Add health checks for Azure Container Apps
builder.Services.AddHealthChecks();

// Register Cosmos DB Client as a singleton for dependency injection
builder.Services.AddSingleton(sp =>
{
    var logger = sp.GetRequiredService<ILogger<Program>>();
    var configuration = sp.GetRequiredService<IConfiguration>();
    
    return CosmosClientFactory.CreateCosmosClient(configuration, logger);
});

// Register services for dependency injection
builder.Services.AddScoped<AzureCosmosDB.MCP.Toolkit.Services.CosmosDbToolsService>();
builder.Services.AddScoped<AzureCosmosDB.MCP.Toolkit.Services.AuthenticationService>();
builder.Services.AddSingleton<AzureCosmosDB.MCP.Toolkit.Services.McpToolRequestValidator>();

// Register MCP server with SDK transport (Streamable HTTP) for the artifact's page and other MCP clients.
// Stateless: every POST stands alone, so browsers need no Mcp-Session-Id and any replica can answer.
// Only the artifact database tools (Artifact/ArtifactDbTools.cs) are served at /mcp: the toolkit's own tools
// read any container directly and would bypass the artifact's rules.
builder.Services.AddHttpContextAccessor();
builder.Services.AddMcpServer()
    .WithHttpTransport(options => options.Stateless = true)
    .WithTools<AzureCosmosDB.MCP.Toolkit.Artifact.ArtifactDbTools>();

// Configure forwarded headers for proxy scenarios
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

// Store configuration in static state for access by static tool methods
AppState.Configuration = builder.Configuration;

// Add security headers middleware to allow MSAL authentication
app.Use(async (context, next) =>
{
    // Fix COOP policy to allow MSAL popup authentication
    context.Response.Headers["Cross-Origin-Opener-Policy"] = "unsafe-none";
    context.Response.Headers["Cross-Origin-Embedder-Policy"] = "unsafe-none";
    
    await next();
});

// Add request logging middleware with User-Agent tracking
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    var path = context.Request.Path.Value ?? "";
    var method = context.Request.Method;
    var rawUserAgent = context.Request.Headers["User-Agent"].ToString();
    var userAgent = Program.NormalizeUserAgentForTelemetry(
        rawUserAgent,
        out var userAgentOriginalLength,
        out var userAgentWasTruncated,
        out var userAgentControlCharsRemoved);
    var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    
    // Log a normalized, bounded User-Agent value to reduce telemetry/dashboard abuse risk.
    logger.LogInformation(
        "Request: {Method} {Path} | User-Agent: {UserAgent} | UA-Original-Length: {UserAgentOriginalLength} | UA-Truncated: {UserAgentWasTruncated} | UA-ControlChars-Removed: {UserAgentControlCharsRemoved} | Client-IP: {ClientIp}", 
        method, path, userAgent, userAgentOriginalLength, userAgentWasTruncated, userAgentControlCharsRemoved, clientIp);
    
    // Detailed logging for MCP endpoints
    if (path.StartsWith("/mcp", StringComparison.OrdinalIgnoreCase))
    {
        logger.LogInformation("=== MCP REQUEST DETAILS ===");
        logger.LogInformation("Method: {Method}, Path: {Path}", method, path);
        logger.LogInformation("User-Agent: {UserAgent}", userAgent);
        logger.LogInformation("Client-IP: {ClientIp}", clientIp);
        
        // Log other relevant headers (excluding sensitive data)
        if (context.Request.Headers.ContainsKey("Content-Type"))
            logger.LogInformation("Content-Type: {ContentType}", context.Request.Headers["Content-Type"].ToString());
        if (context.Request.Headers.ContainsKey("Accept"))
            logger.LogInformation("Accept: {Accept}", context.Request.Headers["Accept"].ToString());
        if (context.Request.Headers.ContainsKey("Referer"))
            logger.LogInformation("Referer: {Referer}", context.Request.Headers["Referer"].ToString());
        
        logger.LogInformation("=== END MCP REQUEST ===");
    }
    
    await next();
});

// Configure forwarded headers
app.UseForwardedHeaders();

// Add health check endpoint for container orchestrators
app.MapHealthChecks("/health");

// Enable CORS
app.UseCors("MCPPolicy");


// Add routing first
app.UseRouting();

// Then authentication and authorization middleware (MUST be after UseRouting and before MapControllers)
app.UseAuthentication();
app.UseAuthorization();

// Development mode logging
if (isDevelopment || devBypassAuth)
{
    app.Logger.LogInformation("Running in development mode with authentication bypass");
}

// Map controllers last
app.MapControllers();

// Map MCP SDK endpoint at /mcp — Streamable HTTP (POST /mcp), stateless.
// This is what AI Foundry, Claude Desktop, and other standard MCP clients connect to.
// The custom /mcp/http controller endpoint is retained for the built-in web UI tester.
if (!devBypassAuth)
{
    if (!string.IsNullOrEmpty(tenantId) && !string.IsNullOrEmpty(clientId))
    {
        // OAuth authorization server metadata (RFC 8414) at this server's root, pointing at Entra. MCP clients that
        // find no protected resource metadata fall back to this, and then sign in with Entra without a resource
        // parameter. There's no registration endpoint: clients use a pre-registered client ID (and secret).
        var entra = $"https://login.microsoftonline.com/{tenantId}";
        app.MapGet("/.well-known/oauth-authorization-server", () => Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = $"{entra}/v2.0",
            ["authorization_endpoint"] = $"{entra}/oauth2/v2.0/authorize",
            ["token_endpoint"] = $"{entra}/oauth2/v2.0/token",
            ["jwks_uri"] = $"{entra}/discovery/v2.0/keys",
            ["response_types_supported"] = new[] { "code" },
            ["grant_types_supported"] = new[] { "authorization_code", "refresh_token" },
            ["code_challenge_methods_supported"] = new[] { "S256" },
            ["token_endpoint_auth_methods_supported"] = new[] { "client_secret_post", "client_secret_basic" },
            ["scopes_supported"] = new[] { $"{clientId}/.default", "offline_access", "openid", "profile" },
        }));
    }
    app.MapMcp("/mcp").RequireAuthorization();
    app.MapGet("/events", AzureCosmosDB.MCP.Toolkit.Artifact.ArtifactEventsEndpoint.Handle).RequireAuthorization();
    app.MapGet("/me", AzureCosmosDB.MCP.Toolkit.Artifact.ArtifactViewer.Me).RequireAuthorization();
}
else
{
    app.MapMcp("/mcp");
    app.MapGet("/events", AzureCosmosDB.MCP.Toolkit.Artifact.ArtifactEventsEndpoint.Handle);
    app.MapGet("/me", AzureCosmosDB.MCP.Toolkit.Artifact.ArtifactViewer.Me);
}

// No web UI: the toolkit's tester (wwwroot, /api/mcp and /mcp/http) served its own tools without the artifact's
// rules, /api/mcp without authentication, so it is removed. /mcp, /events and /health remain.

app.Run();

// Static configuration holder for access in static tool methods
internal static class AppState
{
    public static IConfiguration? Configuration { get; set; }
}

public partial class Program
{
    private const int MaxUserAgentLength = 256;

    public static string NormalizeUserAgentForTelemetry(string? userAgent, out int originalLength, out bool wasTruncated, out int controlCharsRemoved)
    {
        originalLength = userAgent?.Length ?? 0;
        wasTruncated = false;
        controlCharsRemoved = 0;

        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return "Not-Specified";
        }

        var normalized = userAgent.Normalize(NormalizationForm.FormKC);
        var sb = new StringBuilder(normalized.Length);

        foreach (var ch in normalized)
        {
            if (char.IsControl(ch))
            {
                controlCharsRemoved++;
                continue;
            }

            sb.Append(ch);
        }

        var sanitized = sb.ToString().Trim();
        if (sanitized.Length == 0)
        {
            return "Not-Specified";
        }

        if (sanitized.Length > MaxUserAgentLength)
        {
            wasTruncated = true;
            sanitized = sanitized[..MaxUserAgentLength];
        }

        return sanitized;
    }
}

[McpServerToolType]
public static class CosmosDbTools
{
    // Environment variables used:
    // COSMOS_ENDPOINT - Cosmos DB account endpoint
    // OPENAI_ENDPOINT - Azure AI Services account endpoint, e.g. https://<resource>.cognitiveservices.azure.com/
    //                   Do NOT use Foundry project URLs (https://*.services.ai.azure.com/api/projects/...)
    // OPENAI_EMBEDDING_DEPLOYMENT - Embedding model deployment name (e.g. text-embedding-3-small)
    // Auth uses Entra ID via DefaultAzureCredential (supports Managed Identity and service principals).

    [McpServerTool, Description("Lists databases available in the Cosmos DB account.")]
    public static async Task<string> ListDatabases()
    {
        try
        {
            var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }

            var credential = new DefaultAzureCredential();
            // ApplicationName is emitted in the Cosmos SDK UserAgent and surfaces in
            // DailyUserAgentSummary telemetry. Format: "AzureCosmosDBMCP-<kebab-tool-name>".
            // When adding a new [McpServerTool], set its own suffix here so per-tool
            // dashboards keep working. See docs/specs/tool-name-in-useragent.md.
            using var client = new CosmosClient(endpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-list-databases"
            });

            var results = new List<string>();
            var iterator = client.GetDatabaseQueryIterator<DatabaseProperties>();
            while (iterator.HasMoreResults)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var db in page)
                {
                    results.Add(db.Id);
                }
            }

            return JsonSerializer.Serialize(results);
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Lists containers (collections) for the specified database.")]
    public static async Task<string> ListCollections(
        [Description("Database id to list containers from")] string databaseId)
    {
        try
        {
            var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }

            if (string.IsNullOrWhiteSpace(databaseId))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'databaseId' is required." });
            }

            var credential = new DefaultAzureCredential();
            using var client = new CosmosClient(endpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-list-collections"
            });

            var db = client.GetDatabase(databaseId);
            var results = new List<string>();
            var iterator = db.GetContainerQueryIterator<ContainerProperties>();
            while (iterator.HasMoreResults)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var c in page)
                {
                    results.Add(c.Id);
                }
            }

            return JsonSerializer.Serialize(results);
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Gets the most recent N documents ordered by timestamp (_ts DESC) from the specified database/container. N must be between 1 and 20.")]
    public static async Task<string> GetRecentDocuments(
        [Description("Database id containing the container")] string databaseId,
        [Description("Container id to query")] string containerId,
        [Description("Number of documents to return (1-20)")] int n)
    {
        try
        {
            var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(databaseId) || string.IsNullOrWhiteSpace(containerId))
            {
                return JsonSerializer.Serialize(new { error = "Parameters 'databaseId' and 'containerId' are required." });
            }
            if (n < 1 || n > 20)
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'n' must be a whole number between 1 and 20." });
            }

            var credential = new DefaultAzureCredential();
            using var client = new CosmosClient(endpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-get-recent-documents"
            });

            var container = client.GetContainer(databaseId, containerId);
            var queryText = $"SELECT TOP {n} * FROM c ORDER BY c._ts DESC";
            var iterator = container.GetItemQueryIterator<dynamic>(
                new QueryDefinition(queryText),
                requestOptions: new QueryRequestOptions { MaxItemCount = n }
            );

            var jsonDocs = new List<string>();
            while (iterator.HasMoreResults && jsonDocs.Count < n)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var doc in page)
                {
                    jsonDocs.Add(doc?.ToString() ?? "{}");
                    if (jsonDocs.Count >= n) break;
                }
            }

            var jsonArray = "[" + string.Join(",", jsonDocs) + "]";
            return jsonArray;
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Select TOP N documents where a given property contains the provided search string. N must be between 1 and 20.")]
    public static async Task<string> TextSearch(
        [Description("Database id containing the container")] string databaseId,
        [Description("Container id to query")] string containerId,
        [Description("Document property to search, e.g. name or profile.name")] string property,
        [Description("Search term to look for within the property")] string searchPhrase,
        [Description("Number of documents to return (1-20, default 10)")] int n = 10)
    {
        try
        {
            var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(databaseId) || string.IsNullOrWhiteSpace(containerId))
            {
                return JsonSerializer.Serialize(new { error = "Parameters 'databaseId' and 'containerId' are required." });
            }
            if (string.IsNullOrWhiteSpace(property))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'property' is required." });
            }
            if (n < 1 || n > 20)
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'n' must be a whole number between 1 and 20." });
            }

            // Basic validation to avoid injection in the property path: allow letters, digits, underscore and dot segments.
            var propPattern = new Regex(@"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$");
            if (!propPattern.IsMatch(property))
            {
                return JsonSerializer.Serialize(new { error = "Invalid property name. Use dot notation with letters, digits, and underscores only (e.g., name or profile.name)." });
            }

            var credential = new DefaultAzureCredential();
            using var client = new CosmosClient(endpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-text-search"
            });

            var container = client.GetContainer(databaseId, containerId);
            var queryText = $"SELECT TOP {n} * FROM c WHERE FullTextContains(c.{property}, @searchPhrase) ";
            var query = new QueryDefinition(queryText).WithParameter("@searchPhrase", searchPhrase);

            var iterator = container.GetItemQueryIterator<dynamic>(query, requestOptions: new QueryRequestOptions { MaxItemCount = n });

            var jsonDocs = new List<string>();
            while (iterator.HasMoreResults && jsonDocs.Count < n)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var doc in page)
                {
                    jsonDocs.Add(doc?.ToString() ?? "{}");
                    if (jsonDocs.Count >= n) break;
                }
            }

            var jsonArray = "[" + string.Join(",", jsonDocs) + "]";
            return jsonArray;
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Find a document by its id in the specified database/container.")]
    public static async Task<string> FindDocumentByID(
        [Description("Database id containing the container")] string databaseId,
        [Description("Container id to query")] string containerId,
        [Description("The id of the document to find")] string id)
    {
        try
        {
            var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(databaseId) || string.IsNullOrWhiteSpace(containerId))
            {
                return JsonSerializer.Serialize(new { error = "Parameters 'databaseId' and 'containerId' are required." });
            }
            if (string.IsNullOrWhiteSpace(id))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'id' is required." });
            }

            var credential = new DefaultAzureCredential();
            using var client = new CosmosClient(endpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-find-document-by-id"
            });

            var container = client.GetContainer(databaseId, containerId);
            var queryText = "SELECT * FROM c WHERE c.id = @id";
            var query = new QueryDefinition(queryText).WithParameter("@id", id);

            var iterator = container.GetItemQueryIterator<dynamic>(query, requestOptions: new QueryRequestOptions { MaxItemCount = 1 });

            while (iterator.HasMoreResults)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var doc in page)
                {
                    return doc?.ToString() ?? "{}";
                }
            }

            return JsonSerializer.Serialize(new { message = "No document found with the specified id." });
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Approximates a container schema by sampling up to 10 documents and returning a union of top-level properties with inferred types and brief descriptions.")]
    public static async Task<string> GetApproximateSchema(
        [Description("Database id containing the container")] string databaseId,
        [Description("Container id to inspect")] string containerId)
    {
        try
        {
            var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(databaseId) || string.IsNullOrWhiteSpace(containerId))
            {
                return JsonSerializer.Serialize(new { error = "Parameters 'databaseId' and 'containerId' are required." });
            }

            var credential = new DefaultAzureCredential();
            using var client = new CosmosClient(endpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-get-approximate-schema"
            });

            var container = client.GetContainer(databaseId, containerId);
            var queryText = "SELECT TOP 10 * FROM c";
            var iterator = container.GetItemQueryIterator<dynamic>(
                new QueryDefinition(queryText),
                requestOptions: new QueryRequestOptions { MaxItemCount = 10 }
            );

            var typeMap = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var countMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int sampleCount = 0;

            while (iterator.HasMoreResults && sampleCount < 10)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var doc in page)
                {
                    var json = doc?.ToString();
                    if (string.IsNullOrWhiteSpace(json)) continue;

                    try
                    {
                        using var parsed = JsonDocument.Parse(json);
                        if (parsed.RootElement.ValueKind != JsonValueKind.Object) continue;
                        sampleCount++;
                        
                        foreach (var prop in parsed.RootElement.EnumerateObject())
                        {
                            var name = prop.Name;
                            var kind = prop.Value.ValueKind;
                            string type = kind switch
                            {
                                JsonValueKind.String => "string",
                                JsonValueKind.Number => "number",
                                JsonValueKind.True => "boolean",
                                JsonValueKind.False => "boolean",
                                JsonValueKind.Object => "object",
                                JsonValueKind.Array => "array",
                                JsonValueKind.Null => "null",
                                _ => "unknown"
                            };

                            if (!typeMap.TryGetValue(name, out HashSet<string>? set))
                            {
                                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                typeMap[name] = set;
                            }
                            set!.Add(type);

                            countMap.TryGetValue(name, out int current);
                            countMap[name] = current + 1;
                        }
                    }
                    catch
                    {
                        // Ignore malformed JSON rows
                    }

                    if (sampleCount >= 10) break;
                }
            }

            if (sampleCount == 0)
            {
                return JsonSerializer.Serialize(new { message = "No documents found to infer schema." });
            }

            var properties = new List<object>();
            foreach (var kvp in typeMap.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var name = kvp.Key;
                var types = kvp.Value.OrderBy(t => t).ToArray();
                var typeStr = string.Join(" | ", types);
                countMap.TryGetValue(name, out int appearCount);
                var description = $"Appears in {appearCount}/{sampleCount} sampled documents.";
                properties.Add(new { name, type = typeStr, description });
            }

            var result = new { sampleSize = sampleCount, properties };
            return JsonSerializer.Serialize(result);
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Performs vector search on Cosmos DB using Azure OpenAI embeddings. Searches for semantically similar documents based on text input.")]
    public static async Task<string> VectorSearch(
        [Description("Database id containing the container")] string databaseId,
        [Description("Container id to query")] string containerId,
        [Description("Text to search for semantically similar content")] string searchText,
        [Description("Property name where vector embeddings are stored, e.g. 'vector' or 'embeddings'")] string vectorProperty,
        [Description("Comma-separated list of specific properties to project in results, e.g. 'id,title,content'. Cannot use '*' wildcard.")] string selectProperties,
        [Description("Number of documents to return (1-50, default 10)")] int topN = 10)
    {
        try
        {
            // Validate environment variables
            var cosmosEndpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            // OPENAI_ENDPOINT must be the Azure AI Services account endpoint, not a Foundry project URL
            // Microsoft Foundry projects expose OpenAI-compatible endpoints (recommended)
            var openaiEndpoint = Environment.GetEnvironmentVariable("OPENAI_ENDPOINT");
            var embeddingDeployment = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_DEPLOYMENT");

            if (string.IsNullOrWhiteSpace(cosmosEndpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(openaiEndpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable OPENAI_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(embeddingDeployment))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable OPENAI_EMBEDDING_DEPLOYMENT." });
            }

            // Validate parameters
            if (string.IsNullOrWhiteSpace(databaseId) || string.IsNullOrWhiteSpace(containerId))
            {
                return JsonSerializer.Serialize(new { error = "Parameters 'databaseId' and 'containerId' are required." });
            }
            if (string.IsNullOrWhiteSpace(searchText))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'searchText' is required." });
            }
            if (string.IsNullOrWhiteSpace(vectorProperty))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'vectorProperty' is required." });
            }
            if (string.IsNullOrWhiteSpace(selectProperties))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'selectProperties' is required." });
            }
            if (topN < 1 || topN > 50)
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'topN' must be a whole number between 1 and 50." });
            }

            // Validate that selectProperties doesn't contain wildcard
            if (selectProperties.Trim() == "*" || selectProperties.Contains("*"))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'selectProperties' cannot contain '*' wildcard. Please specify explicit property names separated by commas." });
            }

            // Validate property names (without c. prefix - we'll add it later)
            var propPattern = new Regex(@"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$");
            
            // Validate vectorProperty
            if (!propPattern.IsMatch(vectorProperty))
            {
                return JsonSerializer.Serialize(new { error = "Invalid vectorProperty name. Use dot notation with letters, digits, and underscores only (e.g., 'vector' or 'embeddings')." });
            }

            // Validate selectProperties format - each property should be valid
            var properties = selectProperties.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim())
                .ToArray();
            
            foreach (var prop in properties)
            {
                if (!propPattern.IsMatch(prop))
                {
                    return JsonSerializer.Serialize(new { error = $"Invalid property name '{prop}' in selectProperties. Use dot notation with letters, digits, and underscores only (e.g., 'id', 'title', 'metadata.author')." });
                }
            }

            var credential = new DefaultAzureCredential();

            // Generate embedding using the appropriate embedding service
            // (Azure AI Services, OpenAI native, or Azure AI Foundry)
            float[] embedding;
            try
            {
                if (AppState.Configuration == null)
                {
                    return JsonSerializer.Serialize(new { error = "Application configuration not initialized." });
                }
                
                var embeddingClient = EmbeddingClientFactory.CreateEmbeddingClient(AppState.Configuration);
                embedding = await embeddingClient.GenerateEmbeddingAsync(searchText, embeddingDeployment);
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = $"Failed to generate embedding: {ex.Message}" });
            }

            // Perform vector search in Cosmos DB
            using var cosmosClient = new CosmosClient(cosmosEndpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-vector-search"
            });

            var container = cosmosClient.GetContainer(databaseId, containerId);

            // Build SELECT clause by prepending "c." to each property
            var selectClause = string.Join(", ", properties.Select(p => $"c.{p}"));

            // Build vector search query - prepend "c." to vectorProperty as well
            var queryText = $@"
                SELECT TOP @topN {selectClause}, VectorDistance(c.{vectorProperty}, @embedding) as score
                FROM c
                ORDER BY VectorDistance(c.{vectorProperty}, @embedding)";

            var queryDefinition = new QueryDefinition(queryText)
                .WithParameter("@topN", topN)
                .WithParameter("@embedding", embedding);

            var iterator = container.GetItemQueryIterator<dynamic>(
                queryDefinition,
                requestOptions: new QueryRequestOptions { MaxItemCount = topN }
            );

            var results = new List<string>();
            while (iterator.HasMoreResults && results.Count < topN)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var doc in page)
                {
                    results.Add(doc?.ToString() ?? "{}");
                    if (results.Count >= topN) break;
                }
            }

            var jsonArray = "[" + string.Join(",", results) + "]";
            return jsonArray;
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    [McpServerTool, Description("Performs hybrid search combining vector similarity and full-text keyword search using Reciprocal Rank Fusion (RRF). Requires both a vector index and a full-text index on the container.")]
    public static async Task<string> HybridSearch(
        [Description("Database id containing the container")] string databaseId,
        [Description("Container id to query")] string containerId,
        [Description("Text to search for using both semantic similarity and keyword matching")] string searchText,
        [Description("Property name that has a full-text index for keyword search, e.g. 'text' or 'content'")] string textProperty,
        [Description("Property name where vector embeddings are stored, e.g. 'vector' or 'embeddings'")] string vectorProperty,
        [Description("Comma-separated list of specific properties to project in results, e.g. 'id,title,content'. Cannot use '*' wildcard.")] string selectProperties,
        [Description("Number of documents to return (1-50, default 10)")] int topN = 10)
    {
        try
        {
            // Validate environment variables
            var cosmosEndpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
            var openaiEndpoint = Environment.GetEnvironmentVariable("OPENAI_ENDPOINT");
            var embeddingDeployment = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_DEPLOYMENT");

            if (string.IsNullOrWhiteSpace(cosmosEndpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable COSMOS_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(openaiEndpoint))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable OPENAI_ENDPOINT." });
            }
            if (string.IsNullOrWhiteSpace(embeddingDeployment))
            {
                return JsonSerializer.Serialize(new { error = "Missing required environment variable OPENAI_EMBEDDING_DEPLOYMENT." });
            }

            // Validate parameters
            if (string.IsNullOrWhiteSpace(databaseId) || string.IsNullOrWhiteSpace(containerId))
            {
                return JsonSerializer.Serialize(new { error = "Parameters 'databaseId' and 'containerId' are required." });
            }
            if (string.IsNullOrWhiteSpace(searchText))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'searchText' is required." });
            }
            if (string.IsNullOrWhiteSpace(textProperty))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'textProperty' is required." });
            }
            if (string.IsNullOrWhiteSpace(vectorProperty))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'vectorProperty' is required." });
            }
            if (string.IsNullOrWhiteSpace(selectProperties))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'selectProperties' is required." });
            }
            if (topN < 1 || topN > 50)
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'topN' must be a whole number between 1 and 50." });
            }

            // Validate that selectProperties doesn't contain wildcard
            if (selectProperties.Trim() == "*" || selectProperties.Contains("*"))
            {
                return JsonSerializer.Serialize(new { error = "Parameter 'selectProperties' cannot contain '*' wildcard. Please specify explicit property names separated by commas." });
            }

            // Validate property names
            var propPattern = new Regex(@"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$");
            
            if (!propPattern.IsMatch(vectorProperty))
            {
                return JsonSerializer.Serialize(new { error = "Invalid vectorProperty name. Use dot notation with letters, digits, and underscores only (e.g., 'vector' or 'embeddings')." });
            }

            if (!propPattern.IsMatch(textProperty))
            {
                return JsonSerializer.Serialize(new { error = "Invalid textProperty name. Use dot notation with letters, digits, and underscores only (e.g., 'text' or 'content')." });
            }

            var properties = selectProperties.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim())
                .ToArray();
            
            foreach (var prop in properties)
            {
                if (!propPattern.IsMatch(prop))
                {
                    return JsonSerializer.Serialize(new { error = $"Invalid property name '{prop}' in selectProperties. Use dot notation with letters, digits, and underscores only (e.g., 'id', 'title', 'metadata.author')." });
                }
            }

            var credential = new DefaultAzureCredential();

            // Generate embedding using the configured embedding service
            float[] embedding;
            try
            {
                if (AppState.Configuration == null)
                {
                    return JsonSerializer.Serialize(new { error = "Application configuration not initialized." });
                }
                
                var embeddingClient = EmbeddingClientFactory.CreateEmbeddingClient(AppState.Configuration);
                embedding = await embeddingClient.GenerateEmbeddingAsync(searchText, embeddingDeployment);
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = $"Failed to generate embedding: {ex.Message}" });
            }

            // Perform hybrid search in Cosmos DB
            using var cosmosClient = new CosmosClient(cosmosEndpoint, credential, new CosmosClientOptions
            {
                ApplicationName = "AzureCosmosDBMCP-hybrid-search"
            });

            var container = cosmosClient.GetContainer(databaseId, containerId);

            var selectClause = string.Join(", ", properties.Select(p => $"c.{p}"));

            // Hybrid search query using RRF to combine vector and full-text scores
            var queryText = $@"
                SELECT TOP @topN {selectClause}
                FROM c
                ORDER BY RANK RRF(VectorDistance(c.{vectorProperty}, @embedding), FullTextScore(c.{textProperty}, @searchText))";

            var queryDefinition = new QueryDefinition(queryText)
                .WithParameter("@topN", topN)
                .WithParameter("@embedding", embedding)
                .WithParameter("@searchText", searchText);

            var iterator = container.GetItemQueryIterator<dynamic>(
                queryDefinition,
                requestOptions: new QueryRequestOptions { MaxItemCount = topN }
            );

            var results = new List<string>();
            while (iterator.HasMoreResults && results.Count < topN)
            {
                var page = await iterator.ReadNextAsync();
                foreach (var doc in page)
                {
                    results.Add(doc?.ToString() ?? "{}");
                    if (results.Count >= topN) break;
                }
            }

            var jsonArray = "[" + string.Join(",", results) + "]";
            return jsonArray;
        }
        catch (CosmosException cex)
        {
            return JsonSerializer.Serialize(new { error = cex.Message, statusCode = (int)cex.StatusCode });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }
}
