// Who is calling and their level. A caller is identified by their sign-in email, lower-cased (their Entra object ID
// only when the token carries no email), so the same person has the same ID whether they come with a ticket
// (TicketAuthentication.cs) or with an Entra token (the page, Claude).
//
// Their level, first match wins:
//   owner     the principal that deployed the instance: ARTIFACT_OWNER_ID (object ID) or ARTIFACT_OWNER_EMAIL
//   app roles on the MCP server API, for Entra tokens only: Cosmos.Admin → admin, Cosmos.Write → interact,
//             Cosmos.Read → view
//   ARTIFACT_COSMOS_ACCESS, policy.json's cosmos.access as JSON: [{"users": [emails or object IDs], "role": "view" |
//             "interact" | "admin", "containers": [...]}]. The highest role of any entry naming them, so the level
//             says what the Cosmos DB role assignments made from the same list let them do.
// Otherwise they have no level: the db tools and change events refuse them.
//
// The level doesn't grant anything in Cosmos DB, which the db tools reach as the caller: its role assignments decide.
// It is what /me reports, so the page can show or hide what the person may do.
using System.Security.Claims;
using System.Text.Json;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactViewer(string? Id, string? Level, string? Email = null, string? Name = null)
{
    private const string ObjectIdClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private static readonly string[] EmailClaims = ["email", "preferred_username", "upn", "unique_name"];
    private static readonly string[] Levels = ["view", "interact", "admin"]; // lowest first

    public static ArtifactViewer From(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true) return new ArtifactViewer(null, null);
        var throughTicket = user.Identity.AuthenticationType == TicketAuthenticationHandler.SchemeName;
        var oid = user.FindFirst("oid")?.Value ?? user.FindFirst(ObjectIdClaim)?.Value;
        var email = EmailClaims.Select(c => user.FindFirst(c)?.Value).FirstOrDefault(v => v is not null && v.Contains('@'))
            ?.Trim().ToLowerInvariant();
        var roles = throughTicket ? new HashSet<string>() : user.FindAll("roles").Select(c => c.Value).ToHashSet();

        string? level =
            IsOwner(oid, email) ? "owner"
            : roles.Contains("Cosmos.Admin") ? "admin"
            : roles.Contains("Cosmos.Write") ? "interact"
            : roles.Contains("Cosmos.Read") ? "view"
            : Listed(email, oid);
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

    // The highest role cosmos.access gives them, by email or object ID.
    private static string? Listed(string? email, string? oid)
    {
        var best = -1;
        foreach (var (users, role) in Access())
        {
            if ((email is not null && users.Contains(email)) || (oid is not null && users.Contains(oid.ToLowerInvariant())))
                best = Math.Max(best, Array.IndexOf(Levels, role));
        }
        return best < 0 ? null : Levels[best];
    }

    private sealed record Entry(HashSet<string> Users, string Role);
    private sealed record AccessList(string Source, List<Entry> Entries);
    private static AccessList access = new("", []);

    private sealed record EntryJson(string[]? Users, string? Role);

    // ARTIFACT_COSMOS_ACCESS, parsed once per value. Anything malformed grants nothing; an unknown role is skipped.
    private static IEnumerable<(HashSet<string> Users, string Role)> Access()
    {
        var source = Environment.GetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS") ?? "";
        var cached = access;
        if (source != cached.Source)
        {
            var parsed = new List<Entry>();
            try
            {
                var entries = string.IsNullOrWhiteSpace(source) ? null
                    : JsonSerializer.Deserialize<EntryJson[]>(source, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                foreach (var e in entries ?? [])
                {
                    if (e?.Role is not { } role || !Levels.Contains(role)) continue;
                    var users = (e.Users ?? []).Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim().ToLowerInvariant()).ToHashSet();
                    parsed.Add(new Entry(users, role));
                }
            }
            catch (JsonException)
            {
                parsed.Clear();
            }
            cached = access = new AccessList(source, parsed);
        }
        return cached.Entries.Select(e => (e.Users, e.Role));
    }

    // "jane.doe@example.com" → "Jane Doe": a ticket carries no display name.
    private static string? NameFrom(string? email) =>
        email is null ? null
        : string.Join(' ', email[..email.IndexOf('@')].Split('.', '_', '-')
            .Where(p => p.Length > 0).Select(p => char.ToUpperInvariant(p[0]) + p[1..]));
}
