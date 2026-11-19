// A caller's own Cosmos DB token: the fallback for callers without an Entra token for the MCP server's API, who can't
// be served on-behalf-of (CosmosOnBehalfOf.cs). The db tools always call Cosmos DB as the caller, so Cosmos DB's role
// assignments (per container, from policy.json's cosmos.access) decide what they may read, write and delete; see
// docs/cosmos-token-passthrough.md.
//
// It breaks the MCP spec's rule that a server only accepts tokens issued for itself, and no deployed page sends one.
// How it works:
//   - The caller sends the token in the X-Cosmos-Token header next to its ticket, which still says who is signed in.
//   - The token's signature isn't checked here: Cosmos DB checks it on every call. This only refuses tokens that
//     can't be the caller's own: tid must be this tenant (AzureAd__TenantId), exp in the future, aud Cosmos DB
//     (its application ID, as Azure CLI tokens have it, or https://cosmos.azure.com or this account's endpoint,
//     COSMOS_ENDPOINT), and its upn, preferred_username,
//     unique_name or email the caller's sign-in email, so updatedBy stays honest.
//   - One CosmosClient per token (keyed by its SHA-256), dropped once the token expires: a client is expensive to make.
//   - There is no fallback to the server's managed identity, which only reads the change feed for /events.
// The token is never logged.
//
// Claude Code without the app registration: a caller may send the Cosmos DB token itself as
// "Authorization: Bearer <token>" instead of a ticket. Then it also says who is calling, so it is NOT taken on trust:
// Program.cs routes such a bearer (IsCosmosBearer) to the "CosmosToken" JwtBearer scheme, which checks its signature,
// issuer (this tenant) and audience (Audiences) against Entra. ArtifactStore.For then uses that bearer as the Cosmos
// DB token when there's no X-Cosmos-Token header. See docs/cosmos-token-passthrough.md, "Claude Code".
//
// With the app registration, Entra callers need none of this: on-behalf-of (CosmosOnBehalfOf.cs) gets their Cosmos DB
// token for them. This remains for tickets, which can't be exchanged.
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Azure.Cosmos;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public static class CosmosTokenPassthrough
{
    public const string Header = "X-Cosmos-Token";
    public const string SchemeName = "CosmosToken";
    private const int MaxTokenLength = 16 * 1024;
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);
    private static readonly string[] EmailClaims = ["upn", "preferred_username", "unique_name", "email"];

    public sealed record TokenClaims(string Email, DateTimeOffset Expires);

    /// <summary>The token's caller and expiry, or unauthenticated unless it could be <paramref name="email"/>'s own Cosmos DB token.</summary>
    public static TokenClaims Check(string? token, string? email, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(token)) throw Unauthenticated("paste a Cosmos DB token");
        if (string.IsNullOrWhiteSpace(email)) throw Unauthenticated("sign in first");
        if (token.Length > MaxTokenLength) throw Unauthenticated("that isn't a Cosmos DB token");

        JsonElement claims;
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) throw Unauthenticated("that isn't a Cosmos DB token");
            using var doc = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[1]));
            claims = doc.RootElement.Clone();
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
        {
            throw Unauthenticated("that isn't a Cosmos DB token");
        }
        if (claims.ValueKind != JsonValueKind.Object) throw Unauthenticated("that isn't a Cosmos DB token");

        string? Text(string name) =>
            claims.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        var tenant = Environment.GetEnvironmentVariable("AzureAd__TenantId");
        if (string.IsNullOrWhiteSpace(tenant) || !string.Equals(Text("tid"), tenant.Trim(), StringComparison.OrdinalIgnoreCase))
            throw Unauthenticated("the Cosmos DB token is from another tenant; az login --tenant " + tenant);

        if (!claims.TryGetProperty("exp", out var expClaim) || !expClaim.TryGetInt64(out var exp))
            throw Unauthenticated("the Cosmos DB token has no expiry");
        var expires = DateTimeOffset.FromUnixTimeSeconds(exp);
        if (expires <= now + ClockSkew) throw Unauthenticated("the Cosmos DB token has expired; paste a new one");

        if (!Audiences().Contains(Normalize(Text("aud")))) throw Unauthenticated("the token isn't for Cosmos DB");

        var me = email.Trim().ToLowerInvariant();
        if (!EmailClaims.Any(c => string.Equals(Text(c)?.Trim(), me, StringComparison.OrdinalIgnoreCase)))
            throw Unauthenticated("the Cosmos DB token is someone else's; paste your own");

        return new TokenClaims(me, expires);
    }

    // Azure Cosmos DB's application ID, which is what Entra puts in aud for the Azure CLI's tokens whichever resource
    // URL was asked for; and the URL forms: https://cosmos.azure.com and the account's own endpoint (COSMOS_ENDPOINT
    // is https://<account>.documents.azure.com:443/).
    private const string CosmosDbAppId = "a232010e-820c-4083-83bb-3ace5fc29d0b";

    /// <summary>The aud values a Cosmos DB token for this account can carry.</summary>
    public static HashSet<string> Audiences()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { CosmosDbAppId, "https://cosmos.azure.com" };
        if (Uri.TryCreate(Environment.GetEnvironmentVariable("COSMOS_ENDPOINT"), UriKind.Absolute, out var endpoint))
            set.Add($"https://{endpoint.Host}");
        return set;
    }

    /// <summary>
    /// Whether the bearer token is a JWT whose (unverified) aud is Cosmos DB: the request is then
    /// for the CosmosToken scheme, which verifies it. Tickets have two parts, so they never match.
    /// </summary>
    public static bool IsCosmosBearer(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        var token = header[7..].Trim();
        if (token.Length > MaxTokenLength) return false;
        var parts = token.Split('.');
        if (parts.Length != 3) return false;
        try
        {
            using var doc = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[1]));
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("aud", out var aud) && aud.ValueKind == JsonValueKind.String
                && Audiences().Contains(Normalize(aud.GetString()));
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>The bearer token, when the CosmosToken scheme authenticated this request; otherwise null.</summary>
    public static string? VerifiedBearer(HttpContext? context)
    {
        if (context?.User.Identity is not { IsAuthenticated: true, AuthenticationType: SchemeName }) return null;
        var header = context.Request.Headers.Authorization.ToString();
        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : null;
    }

    private static string Normalize(string? aud) =>
        (aud ?? "").Trim().TrimEnd('/').Replace(":443", "", StringComparison.Ordinal);

    private static ArtifactDbException Unauthenticated(string message) => new("unauthenticated", message);

    private sealed record Cached(ArtifactStore Store, CosmosClient Client, DateTimeOffset Expires);
    private static readonly ConcurrentDictionary<string, Cached> Stores = new();

    /// <summary>A store that reaches Cosmos DB with this token, shared by every call that brings the same token.</summary>
    public static ArtifactStore StoreFor(string token, DateTimeOffset expires, DateTimeOffset now) =>
        StoreFor(token, () => new StaticTokenCredential(token, expires), expires, now);

    /// <summary>
    /// A store per key (a token, hashed) with the credential made for it, until <paramref name="expires"/>: shared
    /// with on-behalf-of (CosmosOnBehalfOf.cs), which keys by the caller's bearer token.
    /// </summary>
    public static ArtifactStore StoreFor(string key, Func<TokenCredential> credential, DateTimeOffset expires, DateTimeOffset now)
    {
        foreach (var (k, stale) in Stores)
        {
            if (stale.Expires <= now && Stores.TryRemove(k, out _)) stale.Client.Dispose();
        }
        var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        return Stores.GetOrAdd(id, _ =>
        {
            var client = ArtifactStore.NewClient(credential());
            return new Cached(new ArtifactStore(client), client, expires);
        }).Store;
    }

    /// <summary>The token the caller pasted. Cosmos DB asks for whatever scope it likes; the answer is always this token.</summary>
    private sealed class StaticTokenCredential(string token, DateTimeOffset expires) : TokenCredential
    {
        private readonly AccessToken _token = new(token, expires);

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => _token;

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_token);
    }
}
