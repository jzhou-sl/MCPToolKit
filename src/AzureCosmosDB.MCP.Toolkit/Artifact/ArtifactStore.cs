// The artifact's documents in Cosmos DB (NoSQL API).
//
// Database ARTIFACT_DATABASE (default "artifact"). A top-level collection named in ARTIFACT_CONTAINERS (a JSON list,
// from policy.json's cosmos.containers) has a container of its own, so Cosmos DB role assignments can be scoped to it;
// its nested collections (ideas/i1/comments) live there too. Every other collection is in ARTIFACT_CONTAINER (default
// "docs"). Partition key /collection: every document of one collection shares a partition, so collection scans are
// single-partition. Item ids are the document path with "/" replaced by "|" (Cosmos ids can't contain "/"; "|" isn't
// allowed in path segments). Items: {id, path, collection, docId, data, version, updatedAt, updatedBy}.
//
// Which identity reaches Cosmos DB: the server's managed identity (Shared), or with COSMOS_TOKEN_PASSTHROUGH on, the
// caller's own Cosmos DB token (For, CosmosTokenPassthrough.cs), so Cosmos DB refuses what they may not do. Its
// refusals are permission_denied (403) and unauthenticated (401).
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Identity;
using Microsoft.Azure.Cosmos;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactRecord(string Path, string Id, JsonObject Data, long Version, string? UpdatedAt);

public sealed class ArtifactStore
{
    /// <summary>The server's own client (managed identity): every call without passthrough, and the change feed.</summary>
    public static ArtifactStore Shared { get; } = new(new Lazy<CosmosClient>(() => NewClient(new DefaultAzureCredential())));

    /// <summary>The store for this call: the caller's own token with passthrough on (never the managed identity), else Shared.</summary>
    public static ArtifactStore For(HttpContext? context, ArtifactViewer viewer)
    {
        if (!CosmosTokenPassthrough.Enabled) return Shared;
        var token = context?.Request.Headers[CosmosTokenPassthrough.Header].ToString().Trim();
        var now = DateTimeOffset.UtcNow;
        var claims = CosmosTokenPassthrough.Check(token, viewer.Email, now);
        return CosmosTokenPassthrough.StoreFor(token!, claims.Expires, now);
    }

    internal static CosmosClient NewClient(TokenCredential credential)
    {
        var endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint)) throw new ArtifactDbException("unavailable", "COSMOS_ENDPOINT is not set");
        return new CosmosClient(endpoint, credential, new CosmosClientOptions { ApplicationName = "AzureCosmosDBMCP-artifact-db" });
    }

    private readonly Lazy<CosmosClient> _client;

    public ArtifactStore(CosmosClient client) : this(new Lazy<CosmosClient>(client)) { }

    private ArtifactStore(Lazy<CosmosClient> client)
    {
        _client = client;
    }

    private static string Database => Environment.GetEnvironmentVariable("ARTIFACT_DATABASE") ?? "artifact";

    private static string DefaultContainer => Environment.GetEnvironmentVariable("ARTIFACT_CONTAINER") ?? "docs";

    private sealed record ContainerList(string Source, IReadOnlySet<string> Names);
    private static ContainerList containers = new("", new HashSet<string>());

    /// <summary>ARTIFACT_CONTAINERS, parsed once per value. Anything malformed names none.</summary>
    public static IReadOnlySet<string> OwnContainers()
    {
        var source = Environment.GetEnvironmentVariable("ARTIFACT_CONTAINERS") ?? "";
        var cached = containers;
        if (source == cached.Source) return cached.Names;
        var names = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            if (!string.IsNullOrWhiteSpace(source) && JsonSerializer.Deserialize<string[]>(source) is { } list)
                names.UnionWith(list.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()));
        }
        catch (JsonException)
        {
            names.Clear();
        }
        containers = new ContainerList(source, names);
        return names;
    }

    /// <summary>The container a document or collection path lives in: its first segment's own, or the default.</summary>
    public static string ContainerName(string path)
    {
        var slash = path.IndexOf('/');
        var top = slash < 0 ? path : path[..slash];
        return OwnContainers().Contains(top) ? top : DefaultContainer;
    }

    private Container ContainerFor(string path) => _client.Value.GetContainer(Database, ContainerName(path));

    /// <summary>Every container the artifact's documents may be in: the default one and each of ARTIFACT_CONTAINERS.</summary>
    internal IReadOnlyList<Container> AllContainers() =>
        new[] { DefaultContainer }.Concat(OwnContainers()).Distinct()
            .Select(c => _client.Value.GetContainer(Database, c)).ToList();

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
        using var response = await ContainerFor(path).UpsertItemStreamAsync(ToStream(item), Partition(path), cancellationToken: ct);
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

            using var response = await ContainerFor(path).ReplaceItemStreamAsync(ToStream(item), ItemId(path), Partition(path),
                new ItemRequestOptions { IfMatchEtag = prev.ETag }, ct);
            if (response.StatusCode == HttpStatusCode.PreconditionFailed) continue;
            EnsureSuccess(response);
            return ToRecord(item);
        }
        throw new ArtifactDbException("resource_exhausted", "too many concurrent writes to this document");
    }

    public async Task RemoveAsync(string path, CancellationToken ct)
    {
        using var response = await ContainerFor(path).DeleteItemStreamAsync(ItemId(path), Partition(path), cancellationToken: ct);
        if (response.StatusCode != HttpStatusCode.NotFound) EnsureSuccess(response);
    }

    public async Task<List<ArtifactRecord>> ListAsync(string collection, CancellationToken ct)
    {
        var query = new QueryDefinition("SELECT TOP @n * FROM c WHERE c.collection = @c")
            .WithParameter("@n", ArtifactQuery.MaxScan + 1)
            .WithParameter("@c", collection);
        var records = new List<ArtifactRecord>();
        using var iterator = ContainerFor(collection).GetItemQueryStreamIterator(query, requestOptions: new QueryRequestOptions { PartitionKey = new PartitionKey(collection) });
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
        using var response = await ContainerFor(path).ReadItemStreamAsync(ItemId(path), Partition(path), cancellationToken: ct);
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
        throw ErrorFor(response.StatusCode, response.Headers["x-ms-substatus"], response.ErrorMessage);
    }

    /// <summary>The contract's error for a Cosmos DB failure. 403 and 401 carry Cosmos DB's reason, which names the missing permission.</summary>
    public static ArtifactDbException ErrorFor(HttpStatusCode status, string? substatus, string? message) => status switch
    {
        HttpStatusCode.Forbidden => new ArtifactDbException("permission_denied", Reason("Cosmos DB refused this", substatus, message)),
        HttpStatusCode.Unauthorized => new ArtifactDbException("unauthenticated", Reason("Cosmos DB refused the token; paste a new one", substatus, message)),
        HttpStatusCode.TooManyRequests => new ArtifactDbException("resource_exhausted", "the database is busy; slow down"),
        HttpStatusCode.RequestEntityTooLarge => ArtifactDbException.Invalid("the document is too large"),
        _ => new ArtifactDbException("unavailable", $"the database could not be reached ({(int)status})"),
    };

    // Cosmos DB's message, first line only and trimmed: it can be long, and later lines are diagnostics.
    private static string Reason(string summary, string? substatus, string? message)
    {
        var first = (message ?? "").Split('\n', 2)[0].Trim();
        if (first.Length > 400) first = first[..400] + "...";
        var sub = string.IsNullOrWhiteSpace(substatus) || substatus == "0" ? "" : $" (substatus {substatus})";
        return first.Length == 0 ? summary + sub : $"{summary}{sub}: {first}";
    }
}
