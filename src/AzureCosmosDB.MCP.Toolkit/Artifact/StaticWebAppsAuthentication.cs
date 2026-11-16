// Sign-in through the artifact's Static Web App, which is linked to this server as its backend. The Static Web App
// signs people in with its preconfigured Microsoft Entra provider (a registration Microsoft owns, so the artifact
// needs none of its own) and proxies /api/* here, adding x-ms-client-principal: base64 JSON
// {identityProvider, userId, userDetails, userRoles}. userDetails is the person's sign-in name (their email);
// userId is specific to the Static Web App, not their Entra object ID.
//
// The header is trusted on /api/* only, and nowhere else: the Container App's built-in authentication (the
// "Azure Static Web Apps (Linked)" provider that linking adds) lets only traffic proxied by the Static Web App reach
// those paths, while /mcp, /events and /me are excluded from it and validate Entra tokens here (Claude).
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed class StaticWebAppsAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "StaticWebApps";
    public const string PolicyName = "StaticWebApps";
    public const string PathPrefix = "/api";
    private const string Header = "x-ms-client-principal";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Path.StartsWithSegments(PathPrefix)) return Task.FromResult(AuthenticateResult.NoResult());
        var header = Request.Headers[Header].ToString();
        if (string.IsNullOrEmpty(header)) return Task.FromResult(AuthenticateResult.NoResult());
        var principal = Parse(header);
        if (principal is null)
        {
            Logger.LogWarning("Ignored an {Header} that isn't a signed-in Microsoft Entra user with an email", Header);
            return Task.FromResult(AuthenticateResult.Fail($"unrecognised {Header}"));
        }
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    /// <summary>The person in an x-ms-client-principal header, or null unless it's an Entra ("aad") sign-in with an email.</summary>
    public static ClaimsPrincipal? Parse(string header)
    {
        try
        {
            using var doc = JsonDocument.Parse(Convert.FromBase64String(header));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            string? Text(string name) =>
                root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            var email = Text("userDetails")?.Trim();
            if (Text("identityProvider") != "aad" || string.IsNullOrEmpty(email) || !email.Contains('@')) return null;
            var claims = new List<Claim> { new("email", email.ToLowerInvariant()) };
            if (Text("userId") is { } userId) claims.Add(new Claim("swa_user_id", userId));
            return new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return null;
        }
    }
}
