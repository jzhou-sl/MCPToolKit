// Who is calling and their level. A caller is identified by their sign-in email, lower-cased (their Entra object ID
// only when the token carries no email), so the same person has the same ID whether they come through the artifact's
// Static Web App (a ticket, TicketAuthentication.cs) or with an Entra token (Claude).
//
// Their level, first match wins:
//   owner     the principal that deployed the instance: ARTIFACT_OWNER_ID (object ID) or ARTIFACT_OWNER_EMAIL
//   app roles on the MCP server API, for Entra tokens only: Cosmos.Admin → admin, Cosmos.Write → interact,
//             Cosmos.Read → view
//   ARTIFACT_ACCESS, the access list from the instance's policy.json: {"editors": [emails], "contributors": [...],
//             "viewers": [...]} → admin, interact, view
//   ARTIFACT_DEFAULT_LEVEL (view, interact or admin) for anyone else signed in. Through the Static Web App, whose
//             sign-in admits any Microsoft account, only for emails in ARTIFACT_EMAIL_DOMAINS (comma-separated)
// Otherwise they have no level and can neither read nor write.
using System.Security.Claims;
using System.Text.Json;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactViewer(string? Id, string? Level, string? Email = null, string? Name = null)
{
    private const string ObjectIdClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private static readonly string[] EmailClaims = ["email", "preferred_username", "upn", "unique_name"];

    public static ArtifactViewer From(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true) return new ArtifactViewer(null, null);
        var throughStaticWebApp = user.Identity.AuthenticationType == TicketAuthenticationHandler.SchemeName;
        var oid = user.FindFirst("oid")?.Value ?? user.FindFirst(ObjectIdClaim)?.Value;
        var email = EmailClaims.Select(c => user.FindFirst(c)?.Value).FirstOrDefault(v => v is not null && v.Contains('@'))
            ?.Trim().ToLowerInvariant();
        var roles = throughStaticWebApp ? new HashSet<string>() : user.FindAll("roles").Select(c => c.Value).ToHashSet();

        string? level =
            IsOwner(oid, email) ? "owner"
            : roles.Contains("Cosmos.Admin") ? "admin"
            : roles.Contains("Cosmos.Write") ? "interact"
            : roles.Contains("Cosmos.Read") ? "view"
            : Listed(email) ?? (throughStaticWebApp && !InAllowedDomain(email) ? null : DefaultLevel());
        var name = user.FindFirst("name")?.Value;
        return new ArtifactViewer(email ?? oid, level, email, string.IsNullOrWhiteSpace(name) ? NameFrom(email) : name);
    }

    /// <summary>GET /me: who the caller (a ticket or an Entra token) is to this artifact.</summary>
    public static IResult Me(HttpContext context)
    {
        var v = From(context.User);
        return v.Id is null
            ? Results.Unauthorized()
            : Results.Json(new { id = v.Id, email = v.Email, name = v.Name ?? "", level = v.Level });
    }

    private static bool IsOwner(string? oid, string? email) =>
        Same(oid, Environment.GetEnvironmentVariable("ARTIFACT_OWNER_ID"))
        || Same(email, Environment.GetEnvironmentVariable("ARTIFACT_OWNER_EMAIL"));

    private static bool Same(string? a, string? b) =>
        !string.IsNullOrWhiteSpace(a) && string.Equals(a, b?.Trim(), StringComparison.OrdinalIgnoreCase);

    private static string? Listed(string? email)
    {
        if (email is null) return null;
        foreach (var (group, level) in new[] { ("editors", "admin"), ("contributors", "interact"), ("viewers", "view") })
        {
            if (Access().TryGetValue(group, out var members) && members.Contains(email)) return level;
        }
        return null;
    }

    private sealed record AccessList(string Source, Dictionary<string, HashSet<string>> Groups);
    private static AccessList access = new("", new Dictionary<string, HashSet<string>>());

    // ARTIFACT_ACCESS, parsed once per value. Anything malformed grants nothing.
    private static Dictionary<string, HashSet<string>> Access()
    {
        var source = Environment.GetEnvironmentVariable("ARTIFACT_ACCESS") ?? "";
        var cached = access;
        if (source == cached.Source) return cached.Groups;
        var parsed = new Dictionary<string, HashSet<string>>();
        try
        {
            if (!string.IsNullOrWhiteSpace(source)
                && JsonSerializer.Deserialize<Dictionary<string, string[]>>(source) is { } groups)
            {
                foreach (var (group, members) in groups)
                {
                    parsed[group] = members.Where(m => !string.IsNullOrWhiteSpace(m))
                        .Select(m => m.Trim().ToLowerInvariant()).ToHashSet();
                }
            }
        }
        catch (JsonException)
        {
            parsed.Clear();
        }
        access = new AccessList(source, parsed);
        return parsed;
    }

    private static bool InAllowedDomain(string? email)
    {
        if (email is null) return false;
        var domain = email[(email.LastIndexOf('@') + 1)..];
        return (Environment.GetEnvironmentVariable("ARTIFACT_EMAIL_DOMAINS") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(d => string.Equals(d, domain, StringComparison.OrdinalIgnoreCase));
    }

    private static string? DefaultLevel()
    {
        var level = Environment.GetEnvironmentVariable("ARTIFACT_DEFAULT_LEVEL");
        return level is "view" or "interact" or "admin" ? level : null;
    }

    // "jane.doe@example.com" → "Jane Doe": the Static Web App passes no display name.
    private static string? NameFrom(string? email) =>
        email is null ? null
        : string.Join(' ', email[..email.IndexOf('@')].Split('.', '_', '-')
            .Where(p => p.Length > 0).Select(p => char.ToUpperInvariant(p[0]) + p[1..]));
}
