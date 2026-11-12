// Who is calling, from the validated Entra access token: their object ID, and their level from the app roles on
// the MCP server API (Cosmos.Admin → admin, Cosmos.Write → interact, Cosmos.Read → view). The principal that
// deployed the instance (ARTIFACT_OWNER_ID) is the owner. A signed-in caller with none of these roles gets
// ARTIFACT_DEFAULT_LEVEL (view, interact or admin) if it's set, for app registrations without our app roles;
// otherwise they have no level and can neither read nor write.
using System.Security.Claims;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactViewer(string? Id, string? Level)
{
    private const string ObjectIdClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    public static ArtifactViewer From(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true) return new ArtifactViewer(null, null);
        var id = user.FindFirst("oid")?.Value ?? user.FindFirst(ObjectIdClaim)?.Value;
        var roles = user.FindAll("roles").Select(c => c.Value).ToHashSet();
        var owner = Environment.GetEnvironmentVariable("ARTIFACT_OWNER_ID");

        string? level =
            id is not null && string.Equals(id, owner, StringComparison.OrdinalIgnoreCase) ? "owner"
            : roles.Contains("Cosmos.Admin") ? "admin"
            : roles.Contains("Cosmos.Write") ? "interact"
            : roles.Contains("Cosmos.Read") ? "view"
            : DefaultLevel();
        return new ArtifactViewer(id, level);
    }

    private static string? DefaultLevel()
    {
        var level = Environment.GetEnvironmentVariable("ARTIFACT_DEFAULT_LEVEL");
        return level is "view" or "interact" or "admin" ? level : null;
    }
}
