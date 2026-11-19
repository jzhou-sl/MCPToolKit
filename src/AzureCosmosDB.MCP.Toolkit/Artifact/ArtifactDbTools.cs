// The artifact database as MCP tools, for the artifact's page (window.claude's db) and for agents. Each call reaches
// Cosmos DB as the caller (ArtifactStore.For), with a token got on their behalf for Entra callers (CosmosOnBehalfOf.cs)
// or their own (CosmosTokenPassthrough.cs), so Cosmos DB's role assignments, from policy.json's cosmos.access, alone
// decide what they may do. There are no per-document rules: those roles stop at the container.
//
// A caller who isn't signed in fails with unauthenticated, and one with no level (not the owner, not in
// cosmos.access; ArtifactViewer) with permission_denied, before Cosmos DB is asked. What Cosmos DB refuses fails with
// permission_denied; a missing, expired or someone else's token, or missing consent for on-behalf-of, with
// unauthenticated.
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
    private const string PathDescription = "Document path: an even number of /-separated segments, e.g. tasks/t1";

    [McpServerTool(Name = "db_get", ReadOnly = true, Idempotent = true)]
    [Description("Read one document.")]
    public static Task<CallToolResult> DbGet(
        IHttpContextAccessor http, ILogger<ArtifactDbTools> logger,
        [Description(PathDescription)] string path,
        CancellationToken cancellationToken) =>
        Run(http, logger, async (viewer, store) =>
        {
            ArtifactPaths.Document(path);
            return Snapshot(path, await store.GetAsync(path, cancellationToken));
        });

    [McpServerTool(Name = "db_query", ReadOnly = true, Idempotent = true)]
    [Description("List documents in a collection, optionally filtered (==, !=, <, <=, >, >=, in, not-in, array-contains on top-level fields), ordered and limited.")]
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
            var items = new JsonArray();
            foreach (var r in ArtifactQuery.Run(await store.ListAsync(collection, cancellationToken), query)) items.Add(Snapshot(r.Path, r));
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
            if (viewer.Id is null) throw new ArtifactDbException("unauthenticated", "sign in first");
            if (viewer.Level is null) throw new ArtifactDbException("permission_denied", "you have no access to this artifact");
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
        catch (Exception e) when (CosmosOnBehalfOf.Failure(e) is { } error)
        {
            // Entra refused to exchange the caller's token (CosmosOnBehalfOf.cs). Never log the token itself.
            logger.LogError(e, "Getting a Cosmos DB token on the caller's behalf failed");
            return Fail(error.Code, error.Message);
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
