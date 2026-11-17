// Live updates through Azure Web PubSub (docs/web-pubsub-plan.md in the platform repository). Pages keep a WebSocket
// open to Web PubSub, not to this server: on Azure Functions it can't hold one, and holding streams kept it awake.
// This server is Web PubSub's only other party, and it does two things there:
//   - issues each page a client URL (GET /events/negotiate, ArtifactEvents.cs) whose token puts it in the instance's
//     group and grants no roles, so the page can only receive;
//   - after every db write (ArtifactDbTools), sends {"collection": "<name>"} to that group, so every open page re-reads
//     that collection, whichever Function instance made the write. Deletes included.
// Messages name a collection, never data: pages re-read through db_query, so the artifact's rules still decide.
//
// Settings (main.bicep): WEB_PUBSUB_ENDPOINT, WEB_PUBSUB_HUB, WEB_PUBSUB_GROUP. Without WEB_PUBSUB_ENDPOINT this is off,
// negotiate answers 404 and pages fall back to /events. It authenticates with the server's managed identity
// (DefaultAzureCredential, AZURE_CLIENT_ID): the Web PubSub resource has no access keys.
using Azure.Core;
using Azure.Identity;
using Azure.Messaging.WebPubSub;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public interface IArtifactPubSub
{
    /// <summary>A wss:// URL with a token for this user: joins the group on connect, may only receive.</summary>
    Task<Uri> ClientUrlAsync(string userId, CancellationToken cancellationToken);

    /// <summary>Tells every connected page that this collection changed.</summary>
    Task PublishAsync(string collection, CancellationToken cancellationToken);
}

public sealed class ArtifactPubSub : IArtifactPubSub
{
    // A token only matters while connecting; the page reconnects hourly so access is checked again.
    public static readonly TimeSpan ClientTokenLifetime = TimeSpan.FromMinutes(60);

    // A write has already succeeded when it's published, so a slow or failing Web PubSub only delays it this long.
    public static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(2);

    /// <summary>The configured instance, or null when WEB_PUBSUB_ENDPOINT isn't set. Tests replace it.</summary>
    public static IArtifactPubSub? Shared { get; set; } = FromEnvironment();

    private readonly WebPubSubServiceClient _client;
    private readonly string _group;

    public ArtifactPubSub(WebPubSubServiceClient client, string group)
    {
        _client = client;
        _group = group;
    }

    public static ArtifactPubSub? FromEnvironment()
    {
        var endpoint = Environment.GetEnvironmentVariable("WEB_PUBSUB_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint)) return null;
        var hub = Environment.GetEnvironmentVariable("WEB_PUBSUB_HUB") is { Length: > 0 } h ? h : "artifact";
        var group = Environment.GetEnvironmentVariable("WEB_PUBSUB_GROUP") is { Length: > 0 } g ? g : "changes";
        return new ArtifactPubSub(new WebPubSubServiceClient(new Uri(endpoint), hub, new DefaultAzureCredential()), group);
    }

    public Task<Uri> ClientUrlAsync(string userId, CancellationToken cancellationToken) =>
        _client.GetClientAccessUriAsync(
            expiresAfter: ClientTokenLifetime,
            userId: userId,
            roles: [], // no sendToGroup or joinLeaveGroup: receive only
            groups: [_group],
            cancellationToken: cancellationToken);

    public async Task PublishAsync(string collection, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(SendTimeout);
        await _client.SendToGroupAsync(
            _group,
            RequestContent.Create(new { collection }),
            ContentType.ApplicationJson,
            context: new Azure.RequestContext { CancellationToken = timeout.Token });
    }
}
