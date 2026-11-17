// The artifact database as MCP tools, for the artifact's page (window.claude's db) and for agents. Every call is
// checked against the artifact's rules (ARTIFACT_RULES: capabilities.json's db.rules, as JSON) for the signed-in
// caller (ArtifactViewer). A document the caller may not read looks absent; a write they may not make fails
// with invalid_argument, as the Claude artifact `db` contract says.
//
// With COSMOS_TOKEN_PASSTHROUGH on (test only, CosmosTokenPassthrough.cs) the rules are off: each call reaches
// Cosmos DB with the caller's own token, and Cosmos DB's role assignments alone decide. What it refuses fails with
// permission_denied; a missing, expired or someone else's token fails with unauthenticated before Cosmos DB is called.
//
// Every write tells the artifact's open pages which collection changed (Changed, below): through Web PubSub, and to
// this instance's /events subscribers.
//
// Results: a snapshot is {id, path, exists, data?, version?, updatedAt?}; db_query returns {items: [snapshot]}.
// Errors are tool results with isError and the text "<code>: <message>".
using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Azure.Cosmos;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

[McpServerToolType]
public sealed class ArtifactDbTools
{
    private static readonly Lazy<IReadOnlyList<ArtifactRule>> Rules = new(() =>
        ArtifactRules.Validate(JsonNode.Parse(Environment.GetEnvironmentVariable("ARTIFACT_RULES") ?? "[]")));

    private const string PathDescription = "Document path: an even number of /-separated segments, e.g. tasks/t1";

    [McpServerTool(Name = "db_get", ReadOnly = true, Idempotent = true)]
    [Description("Read one document. A document you may not read looks absent.")]
    public static Task<CallToolResult> DbGet(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        CancellationToken cancellationToken) =>
        Run(http, logger, async (viewer, store) =>
        {
            ArtifactPaths.Document(path);
            var record = Can(path, "read", viewer) ? await store.GetAsync(path, cancellationToken) : null;
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
        Run(http, logger, async (viewer, store) =>
        {
            ArtifactPaths.Collection(collection);
            var query = ArtifactQuery.Check(ToNode(where), ToNode(orderBy), limit);
            var readable = (await store.ListAsync(collection, cancellationToken)).Where(r => Can(r.Path, "read", viewer));
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
        Run(http, logger, async (viewer, store) =>
        {
            ArtifactPaths.Document(path);
            var body = ArtifactPaths.CheckBody(ToNode(data));
            DemandWrite(path, viewer);
            var record = await store.PutAsync(path, body, viewer.Id, cancellationToken);
            await Changed(path, logger);
            return Snapshot(path, record);
        });

    [McpServerTool(Name = "db_update")]
    [Description("Merge fields into an existing document (nested objects merge; arrays replace).")]
    public static Task<CallToolResult> DbUpdate(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        [Description("Fields to merge: a JSON object")] JsonElement data,
        CancellationToken cancellationToken) =>
        Run(http, logger, async (viewer, store) =>
        {
            ArtifactPaths.Document(path);
            var patch = ArtifactPaths.CheckBody(ToNode(data));
            DemandWrite(path, viewer);
            var record = await store.UpdateAsync(path, patch, viewer.Id, cancellationToken)
                ?? throw ArtifactDbException.Invalid("update needs an existing document; use set to create one");
            await Changed(path, logger);
            return Snapshot(path, record);
        });

    [McpServerTool(Name = "db_delete", Destructive = true, Idempotent = true)]
    [Description("Delete one document. Documents nested under it survive.")]
    public static Task<CallToolResult> DbDelete(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        CancellationToken cancellationToken) =>
        Run(http, logger, async (viewer, store) =>
        {
            ArtifactPaths.Document(path);
            DemandWrite(path, viewer);
            await store.RemoveAsync(path, cancellationToken);
            await Changed(path, logger);
            return new JsonObject { ["deleted"] = path };
        });

    /// <summary>After a write: tells every open page through Web PubSub (ArtifactPubSub.cs), whichever instance they
    /// were served by, and this instance's /events subscribers (the local host, pages built without Web PubSub). Deletes
    /// included, which the change feed doesn't report. The write has already succeeded, so a failure to tell anyone is
    /// logged, never returned: pages catch up when they reconnect or the tab is shown again.</summary>
    public static async Task Changed(string path, ILogger logger)
    {
        var collection = ArtifactPaths.Parent(path);
        ArtifactEvents.Shared.Publish(collection);
        if (ArtifactPubSub.Shared is not { } pubsub) return;
        try
        {
            // Not the caller's token: if they go away after the write, the others still need telling.
            await pubsub.PublishAsync(collection, CancellationToken.None);
        }
        catch (Exception e)
        {
            logger.LogWarning(e, "Telling pages through Web PubSub that {Collection} changed failed", collection);
        }
    }

    private static bool Can(string path, string action, ArtifactViewer viewer) =>
        CosmosTokenPassthrough.Enabled || ArtifactRules.CanAccess(Rules.Value, path, action, viewer);

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

    private static async Task<CallToolResult> Run(IHttpContextAccessor http, ILogger logger, Func<ArtifactViewer, ArtifactStore, Task<JsonObject>> work)
    {
        try
        {
            var viewer = ArtifactViewer.From(http.HttpContext?.User);
            var result = await work(viewer, ArtifactStore.For(http.HttpContext, viewer));
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
        catch (CosmosException e)
        {
            // The stream APIs return failures, but setting up a client (reading the account) can throw them.
            var error = ArtifactStore.ErrorFor(e.StatusCode, e.SubStatusCode.ToString(), e.ResponseBody ?? e.Message);
            if (error.Code == "unavailable") logger.LogError(e, "Artifact database call failed");
            return Fail(error.Code, error.Message);
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
