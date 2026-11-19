// On-behalf-of (docs/app-registration-plan.md): a caller who signs in with Entra (Claude Code, Claude, the local host)
// reaches Cosmos DB as themselves with nothing pasted. Their bearer token is for the MCP server's app registration
// (AzureAd__ClientId); the server exchanges it at Entra for a Cosmos DB token for the same person, so Cosmos DB's role
// assignments (per container, from policy.json's cosmos.access) decide.
//
// On whenever the registration's settings are there. Callers without an Entra token (tickets) can still send their
// own Cosmos DB token (CosmosTokenPassthrough.cs); for an Entra caller this wins over that.
//
// The server proves it is the app registration with no secret: a federated credential on the registration trusts the
// Function app's managed identity (AZURE_CLIENT_ID), whose token for api://AzureADTokenExchange is the client
// assertion. The registration also needs an exposed scope (so the caller's token is a delegated one) and consent to
// Azure Cosmos DB's user_impersonation (OBO can't prompt). Failures:
//   AADSTS65001 (no consent)                       → unauthenticated, saying what to consent to;
//   AADSTS700016 / 70021 / 700213 (no federated credential or wrong subject), others → unavailable, logged.
// One CosmosClient per bearer token (CosmosTokenPassthrough.StoreFor's cache), until the bearer expires.
using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public static class CosmosOnBehalfOf
{
    private static readonly string[] ExchangeScope = ["api://AzureADTokenExchange/.default"];

    private static string? Setting(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } v && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;

    public static bool Enabled =>
        Setting("AzureAd__TenantId") is not null && Setting("AzureAd__ClientId") is not null;

    /// <summary>Makes the credential for one caller's bearer token. Tests replace it so they needn't reach Entra.</summary>
    public static Func<string, TokenCredential> CredentialFor { get; set; } = NewCredential;

    public sealed record Bearer(string Token, DateTimeOffset Expires);

    /// <summary>The bearer token and its expiry, when the Entra scheme (Program.cs) authenticated this request; otherwise null.</summary>
    public static Bearer? EntraBearer(HttpContext? context)
    {
        if (context?.User.Identity is not { IsAuthenticated: true, AuthenticationType: JwtBearerDefaults.AuthenticationScheme }) return null;
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        // The scheme has checked exp; without one, keep the client briefly.
        var expires = long.TryParse(context.User.FindFirst("exp")?.Value, out var exp)
            ? DateTimeOffset.FromUnixTimeSeconds(exp)
            : DateTimeOffset.UtcNow.AddMinutes(5);
        return new Bearer(header[7..].Trim(), expires);
    }

    /// <summary>A store that reaches Cosmos DB as the bearer's owner, shared by every call with the same bearer.</summary>
    public static ArtifactStore StoreFor(Bearer bearer, DateTimeOffset now) =>
        CosmosTokenPassthrough.StoreFor("obo:" + bearer.Token, () => CredentialFor(bearer.Token), bearer.Expires, now);

    private static TokenCredential NewCredential(string bearer)
    {
        var identity = Setting("AZURE_CLIENT_ID") is { } id
            ? ManagedIdentityId.FromUserAssignedClientId(id)
            : ManagedIdentityId.SystemAssigned;
        var managedIdentity = new ManagedIdentityCredential(identity);
        return new OnBehalfOfCredential(
            Setting("AzureAd__TenantId"),
            Setting("AzureAd__ClientId"),
            async cancellationToken =>
                (await managedIdentity.GetTokenAsync(new TokenRequestContext(ExchangeScope), cancellationToken)).Token,
            bearer,
            new OnBehalfOfCredentialOptions());
    }

    /// <summary>The tool error for a failed exchange anywhere in <paramref name="e"/>'s chain, or null when it isn't one.</summary>
    public static ArtifactDbException? Failure(Exception e)
    {
        for (var x = e; x is not null; x = x.InnerException)
        {
            if (x is not AuthenticationFailedException && !x.Message.Contains("AADSTS", StringComparison.Ordinal)) continue;
            var text = string.Join(" ", Chain(x).Select(c => c.Message));
            return text.Contains("AADSTS65001", StringComparison.Ordinal)
                ? new ArtifactDbException("unauthenticated",
                    "consent to Azure Cosmos DB (user_impersonation) for the MCP server's app registration first")
                : new ArtifactDbException("unavailable", "the MCP server could not get a Cosmos DB token for you");
        }
        return null;
    }

    private static IEnumerable<Exception> Chain(Exception e)
    {
        for (var x = e; x is not null; x = x.InnerException) yield return x;
    }
}
