// The artifact database as MCP tools, for the artifact's page (window.claude's db) and for agents. Every call is
// checked against the artifact's rules (ARTIFACT_RULES: capabilities.json's db.rules, as JSON) for the signed-in
// caller (ArtifactViewer). A document the caller may not read looks absent; a write they may not make fails
// with invalid_argument, as the Claude artifact `db` contract says.
//
// Results: a snapshot is {id, path, exists, data?, version?, updatedAt?}; db_query returns {items: [snapshot]}.
// Errors are tool results with isError and the text "<code>: <message>".
using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

[McpServerToolType]
public sealed class ArtifactDbTools
{
    private static ArtifactStore Store => ArtifactStore.Shared;

    private static readonly Lazy<IReadOnlyList<ArtifactRule>> Rules = new(() =>
        ArtifactRules.Validate(JsonNode.Parse(Environment.GetEnvironmentVariable("ARTIFACT_RULES") ?? "[]")));

    private const string PathDescription = "Document path: an even number of /-separated segments, e.g. tasks/t1";

    [McpServerTool(Name = "db_get", ReadOnly = true, Idempotent = true)]
    [Description("Read one document. A document you may not read looks absent.")]
    public static Task<CallToolResult> DbGet(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        CancellationToken cancellationToken) =>
        Run(http, logger, async viewer =>
        {
            ArtifactPaths.Document(path);
            var record = Can(path, "read", viewer) ? await Store.GetAsync(path, cancellationToken) : null;
            return Snapshot(path, record);
        });

    [McpServerTool(Name = "db_query", ReadOnly = true, Idempotent = true)]
    [Description("List documents in a collection, optionally filtered (==, !=, <, <=, >, >=, in, not-in, array-contains on top-level fields), ordered and limited. Only documents you may read are returned.")]
    public static Task<CallToolResult> DbQuery(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description("Collection path: an odd number of segments, e.g. tasks")] string collection,
        [Description("Filters: [{field, op, value}], at most 10")] JsonElement? where = null,
        [Description("Order: {field, dir: asc | desc}")] JsonElement? orderBy = null,
        [Description("At most this many documents, 1 to 1000")] int? limit = null,
        CancellationToken cancellationToken = default) =>
        Run(http, logger, async viewer =>
        {
            ArtifactPaths.Collection(collection);
            var query = ArtifactQuery.Check(ToNode(where), ToNode(orderBy), limit);
            var readable = (await Store.ListAsync(collection, cancellationToken)).Where(r => Can(r.Path, "read", viewer));
            var items = new JsonArray();
            foreach (var r in ArtifactQuery.Run(readable, query)) items.Add(Snapshot(r.Path, r));
            return new JsonObject { ["items"] = items };
        });

    [McpServerTool(Name = "db_set", Destructive = true, Idempotent = true)]
    [Description("Create or replace a whole document.")]
    public static Task<CallToolResult> DbSet(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        [Description("Document body: a JSON object")] JsonElement data,
        CancellationToken cancellationToken) =>
        Run(http, logger, async viewer =>
        {
            ArtifactPaths.Document(path);
            var body = ArtifactPaths.CheckBody(ToNode(data));
            DemandWrite(path, viewer);
            var record = await Store.PutAsync(path, body, viewer.Id, cancellationToken);
            Changed(path);
            return Snapshot(path, record);
        });

    [McpServerTool(Name = "db_update")]
    [Description("Merge fields into an existing document (nested objects merge; arrays replace).")]
    public static Task<CallToolResult> DbUpdate(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        [Description("Fields to merge: a JSON object")] JsonElement data,
        CancellationToken cancellationToken) =>
        Run(http, logger, async viewer =>
        {
            ArtifactPaths.Document(path);
            var patch = ArtifactPaths.CheckBody(ToNode(data));
            DemandWrite(path, viewer);
            var record = await Store.UpdateAsync(path, patch, viewer.Id, cancellationToken)
                ?? throw ArtifactDbException.Invalid("update needs an existing document; use set to create one");
            Changed(path);
            return Snapshot(path, record);
        });

    [McpServerTool(Name = "db_delete", Destructive = true, Idempotent = true)]
    [Description("Delete one document. Documents nested under it survive.")]
    public static Task<CallToolResult> DbDelete(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        CancellationToken cancellationToken) =>
        Run(http, logger, async viewer =>
        {
            ArtifactPaths.Document(path);
            DemandWrite(path, viewer);
            await Store.RemoveAsync(path, cancellationToken);
            Changed(path);
            return new JsonObject { ["deleted"] = path };
        });

    // Tell this replica's open pages at once (and about deletes, which the change feed doesn't report).
    private static void Changed(string path) => ArtifactEvents.Shared.Publish(ArtifactPaths.Parent(path));

    private static bool Can(string path, string action, ArtifactViewer viewer) =>
        ArtifactRules.CanAccess(Rules.Value, path, action, viewer);

    private static void DemandWrite(string path, ArtifactViewer viewer)
    {
        // The contract has no permission-denied code: a write below the minimum level is invalid_argument.
        if (!Can(path, "write", viewer)) throw ArtifactDbException.Invalid("you may not write here");
    }

    public static JsonObject Snapshot(string path, ArtifactRecord? record)
    {
        var snap = new JsonObject { ["id"] = ArtifactPaths.Id(path), ["path"] = path, ["exists"] = record is not null };
        if (record is not null)
        {
            snap["data"] = record.Data.DeepClone();
            snap["version"] = record.Version;
            snap["updatedAt"] = record.UpdatedAt;
        }
        return snap;
    }

    private static JsonNode? ToNode(JsonElement? element) =>
        element is { ValueKind: not (JsonValueKind.Undefined or JsonValueKind.Null) } e ? JsonNode.Parse(e.GetRawText()) : null;

    private static async Task<CallToolResult> Run(IHttpContextAccessor http, ILogger logger, Func<ArtifactViewer, Task<JsonObject>> work)
    {
        try
        {
            var result = await work(ArtifactViewer.From(http.HttpContext?.User));
            return new CallToolResult
            {
                Content = [new TextContentBlock { Text = result.ToJsonString() }],
                StructuredContent = JsonSerializer.SerializeToElement(result),
            };
        }
        catch (ArtifactDbException e)
        {
            return Fail(e.Code, e.Message);
        }
        catch (Exception e)
        {
            logger.LogError(e, "Artifact database call failed");
            return Fail("unavailable", "the database could not be reached");
        }
    }

    private static CallToolResult Fail(string code, string message) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = $"{code}: {message}" }],
    };
}
