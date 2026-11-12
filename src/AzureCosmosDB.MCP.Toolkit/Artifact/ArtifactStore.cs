// The artifact's documents in Cosmos DB (NoSQL API), reached with the server's managed identity.
//
// Database ARTIFACT_DATABASE (default "artifact"), container ARTIFACT_CONTAINER (default "docs"), partition key
// /collection: every document of one collection shares a partition, so collection scans are single-partition.
// Item ids are the document path with "/" replaced by "|" (Cosmos ids can't contain "/"; "|" isn't allowed in
// path segments). Items: {id, path, collection, docId, data, version, updatedAt, updatedBy}.
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Azure.Identity;
using Microsoft.Azure.Cosmos;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactRecord(string Path, string Id, JsonObject Data, long Version, string? UpdatedAt);

public sealed class ArtifactStore
{
    private readonly Lazy<Container> _docs = new(() =>
    {
        var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint)) throw new ArtifactDbException("unavailable", "COSMOS_ENDPOINT is not set");
        var client = new CosmosClient(endpoint, new DefaultAzureCredential(), new CosmosClientOptions
        {
            ApplicationName = "AzureCosmosDBMCP-artifact-db",
        });
        return client.GetContainer(
            Environment.GetEnvironmentVariable("ARTIFACT_DATABASE") ?? "artifact",
            Environment.GetEnvironmentVariable("ARTIFACT_CONTAINER") ?? "docs");
    });

    private Container Docs => _docs.Value;

    private static string ItemId(string path) => path.Replace('/', '|');

    private static PartitionKey Partition(string path) => new(ArtifactPaths.Parent(path));

    public async Task<ArtifactRecord?> GetAsync(string path, CancellationToken ct) => ToRecord((await ReadAsync(path, ct))?.Item);

    public async Task<ArtifactRecord> PutAsync(string path, JsonObject data, string? by, CancellationToken ct)
    {
        var prev = await ReadAsync(path, ct);
        var item = new JsonObject
        {
            ["id"] = ItemId(path),
            ["path"] = path,
            ["collection"] = ArtifactPaths.Parent(path),
            ["docId"] = ArtifactPaths.Id(path),
            ["data"] = data,
            ["version"] = (prev?.Item["version"]?.GetValue<long>() ?? 0) + 1,
            ["updatedAt"] = DateTimeOffset.UtcNow.ToString("O"),
            ["updatedBy"] = by,
        };
        using var response = await Docs.UpsertItemStreamAsync(ToStream(item), Partition(path), cancellationToken: ct);
        EnsureSuccess(response);
        return ToRecord(item)!;
    }

    /// <summary>Merges into an existing document; null when there's none. Retries if someone else wrote in between.</summary>
    public async Task<ArtifactRecord?> UpdateAsync(string path, JsonObject patch, string? by, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var prev = await ReadAsync(path, ct);
            if (prev is null) return null;
            var item = prev.Item.DeepClone().AsObject();
            item["data"] = ArtifactQuery.DeepMerge(prev.Item["data"]?.AsObject() ?? [], patch);
            item["version"] = (prev.Item["version"]?.GetValue<long>() ?? 0) + 1;
            item["updatedAt"] = DateTimeOffset.UtcNow.ToString("O");
            item["updatedBy"] = by;
            foreach (var system in new[] { "_rid", "_self", "_etag", "_attachments", "_ts" }) item.Remove(system);

            using var response = await Docs.ReplaceItemStreamAsync(ToStream(item), ItemId(path), Partition(path),
                new ItemRequestOptions { IfMatchEtag = prev.ETag }, ct);
            if (response.StatusCode == HttpStatusCode.PreconditionFailed) continue;
            EnsureSuccess(response);
            return ToRecord(item);
        }
        throw new ArtifactDbException("resource_exhausted", "too many concurrent writes to this document");
    }

    public async Task RemoveAsync(string path, CancellationToken ct)
    {
        using var response = await Docs.DeleteItemStreamAsync(ItemId(path), Partition(path), cancellationToken: ct);
        if (response.StatusCode != HttpStatusCode.NotFound) EnsureSuccess(response);
    }

    public async Task<List<ArtifactRecord>> ListAsync(string collection, CancellationToken ct)
    {
        var query = new QueryDefinition("SELECT TOP @n * FROM c WHERE c.collection = @c")
            .WithParameter("@n", ArtifactQuery.MaxScan + 1)
            .WithParameter("@c", collection);
        var records = new List<ArtifactRecord>();
        using var iterator = Docs.GetItemQueryStreamIterator(query, requestOptions: new QueryRequestOptions { PartitionKey = new PartitionKey(collection) });
        while (iterator.HasMoreResults)
        {
            using var page = await iterator.ReadNextAsync(ct);
            EnsureSuccess(page);
            var body = await JsonNode.ParseAsync(page.Content, cancellationToken: ct);
            foreach (var item in body?["Documents"]?.AsArray() ?? [])
            {
                if (ToRecord(item as JsonObject) is { } r) records.Add(r);
            }
        }
        if (records.Count > ArtifactQuery.MaxScan)
            throw new ArtifactDbException("resource_exhausted", "the collection is too large to scan; narrow the data model");
        return records;
    }

    private sealed record Stored(JsonObject Item, string ETag);

    private async Task<Stored?> ReadAsync(string path, CancellationToken ct)
    {
        using var response = await Docs.ReadItemStreamAsync(ItemId(path), Partition(path), cancellationToken: ct);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        EnsureSuccess(response);
        var item = (await JsonNode.ParseAsync(response.Content, cancellationToken: ct))!.AsObject();
        return new Stored(item, response.Headers.ETag);
    }

    private static ArtifactRecord? ToRecord(JsonObject? item)
    {
        if (item?["path"] is not JsonValue path || item["data"] is not JsonObject data) return null;
        var p = path.GetValue<string>();
        return new ArtifactRecord(p, ArtifactPaths.Id(p), data.DeepClone().AsObject(),
            item["version"]?.GetValue<long>() ?? 0, item["updatedAt"]?.GetValue<string>());
    }

    private static MemoryStream ToStream(JsonObject item) => new(Encoding.UTF8.GetBytes(item.ToJsonString()));

    private static void EnsureSuccess(ResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;
        throw response.StatusCode switch
        {
            HttpStatusCode.TooManyRequests => new ArtifactDbException("resource_exhausted", "the database is busy; slow down"),
            HttpStatusCode.RequestEntityTooLarge => ArtifactDbException.Invalid("the document is too large"),
            _ => new ArtifactDbException("unavailable", $"the database could not be reached ({(int)response.StatusCode})"),
        };
    }
}
