// Pushes "this collection changed" to the artifact's open pages, so their db listeners refresh at once instead of
// polling. Each message names a collection, never data, and the page re-reads through db_query, so Cosmos DB
// still decides what it sees. Two ways to listen:
//   - GET /events/negotiate (ArtifactNegotiateEndpoint, below): a receive-only Web PubSub client URL. Deployed pages
//     use this: they keep a WebSocket open to Web PubSub, which ArtifactDbTools tells about every write
//     (ArtifactPubSub.cs), so the Function app can sleep while they're open. 404 when Web PubSub isn't configured.
//   - GET /events: server-sent events from this instance, fed as described next. Used by the local host
//     (src/local-host) and pages built without Web PubSub.
//
// /events changes come from two places:
//   - Cosmos DB's change feed (latest-version mode, from "now") of every container the artifact uses (the default
//     one and ARTIFACT_CONTAINERS, ArtifactStore.cs), read every second while anyone is subscribed and stopped a
//     minute after the last one leaves. It reports creates and updates made through any replica. It is read with the
//     server's managed identity, a Data Reader: it only ever publishes collection names, never data.
//   - This replica's own writes (db_set, db_update, db_delete), published at once. The change feed doesn't report
//     deletes, so a delete made through another replica reaches /events pages only when they next re-read.
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.Azure.Cosmos;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed class ArtifactEvents
{
    public static ArtifactEvents Shared { get; } = new(() => ArtifactStore.Shared.AllContainers());

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan IdleStop = TimeSpan.FromMinutes(1);

    private static readonly TimeSpan FailureBackoff = TimeSpan.FromSeconds(5);

    private readonly Func<IReadOnlyList<Container>> _containers;
    private readonly ConcurrentDictionary<Guid, Channel<string>> _subscribers = new();
    private readonly object _gate = new();
    private Task? _feed;

    public ArtifactEvents(Func<IReadOnlyList<Container>> containers)
    {
        _containers = containers;
    }

    public ILogger? Logger { get; set; }

    public int SubscriberCount => _subscribers.Count;

    /// <summary>Collections that changed, as they happen. Dispose the subscription to stop.</summary>
    public Subscription Subscribe(bool readChangeFeed = true)
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropOldest });
        _subscribers[id] = channel;
        if (readChangeFeed) EnsureFeed();
        return new Subscription(channel.Reader, () => _subscribers.TryRemove(id, out _));
    }

    public void Publish(string collection)
    {
        foreach (var channel in _subscribers.Values) channel.Writer.TryWrite(collection);
    }

    private void EnsureFeed()
    {
        lock (_gate)
        {
            if (_feed is { IsCompleted: false }) return;
            _feed = Task.Run(ReadChangeFeedAsync);
        }
    }

    // Where one container's change feed is up to.
    private sealed class Feed
    {
        public FeedIterator? Iterator;
        public string? Continuation;
        public DateTimeOffset RetryAt;
    }

    private async Task ReadChangeFeedAsync()
    {
        var idleSince = DateTimeOffset.UtcNow;
        var feeds = new Dictionary<string, Feed>();
        while (true)
        {
            if (_subscribers.IsEmpty)
            {
                if (DateTimeOffset.UtcNow - idleSince > IdleStop) break;
            }
            else
            {
                idleSince = DateTimeOffset.UtcNow;
            }

            IReadOnlyList<Container> containers;
            try
            {
                containers = _containers();
            }
            catch (Exception e)
            {
                Logger?.LogWarning(e, "Reading the artifact change feed failed; retrying");
                await Task.Delay(FailureBackoff);
                continue;
            }

            var changed = false;
            foreach (var container in containers)
            {
                if (!feeds.TryGetValue(container.Id, out var feed)) feeds[container.Id] = feed = new Feed();
                if (DateTimeOffset.UtcNow < feed.RetryAt) continue;
                try
                {
                    feed.Iterator ??= container.GetChangeFeedStreamIterator(
                        feed.Continuation is null ? ChangeFeedStartFrom.Now() : ChangeFeedStartFrom.ContinuationToken(feed.Continuation),
                        ChangeFeedMode.LatestVersion,
                        new ChangeFeedRequestOptions { PageSizeHint = 100 });
                    using var page = await feed.Iterator.ReadNextAsync();
                    feed.Continuation = page.ContinuationToken ?? feed.Continuation;
                    if (page.StatusCode == HttpStatusCode.NotModified) continue;
                    page.EnsureSuccessStatusCode();
                    changed = true;
                    var body = await JsonNode.ParseAsync(page.Content);
                    var collections = (body?["Documents"]?.AsArray() ?? [])
                        .Select(d => d?["collection"]?.GetValue<string>())
                        .Where(c => !string.IsNullOrEmpty(c))
                        .Distinct();
                    foreach (var c in collections) Publish(c!);
                }
                catch (Exception e)
                {
                    // One container failing (not created yet, say) doesn't hold up the others.
                    Logger?.LogWarning(e, "Reading the change feed of container {Container} failed; retrying", container.Id);
                    feed.Iterator = null;
                    feed.RetryAt = DateTimeOffset.UtcNow + FailureBackoff;
                }
            }
            if (!changed) await Task.Delay(PollInterval);
        }
        lock (_gate) _feed = null;
        if (!_subscribers.IsEmpty) EnsureFeed(); // someone subscribed while it was stopping
    }

    public sealed class Subscription(ChannelReader<string> reader, Action unsubscribe) : IDisposable
    {
        public ChannelReader<string> Reader { get; } = reader;

        public void Dispose() => unsubscribe();
    }
}

public static class ArtifactEventsEndpoint
{
    private static readonly TimeSpan Heartbeat = TimeSpan.FromSeconds(25); // under the ingress idle timeout
    // Streams end after this, and the page reconnects: a ticket lasts a minute, so the caller's access is checked again.
    // Under Azure Functions' 230-second limit on an HTTP response, so the stream ends cleanly before the platform cuts it.
    private static readonly TimeSpan MaxStream = TimeSpan.FromSeconds(200);

    /// <summary>Who may hear about changes (GET /events, server-sent events with one "change" per changed collection,
    /// and /events/negotiate): callers with a level, so the owner and the people in policy.json's cosmos.access.</summary>
    public static bool MayListen(ArtifactViewer viewer) => viewer.Level is not null;

    public static async Task Handle(HttpContext context)
    {
        var viewer = ArtifactViewer.From(context.User);
        if (!MayListen(viewer))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        context.Response.Headers.ContentType = "text/event-stream";
        context.Response.Headers.CacheControl = "no-cache";
        context.Response.Headers["X-Accel-Buffering"] = "no";
        var ct = context.RequestAborted;
        await context.Response.WriteAsync(": connected\n\n", ct);
        await context.Response.Body.FlushAsync(ct);

        var events = ArtifactEvents.Shared;
        events.Logger ??= context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger<ArtifactEvents>();
        using var subscription = events.Subscribe();
        var deadline = DateTimeOffset.UtcNow + MaxStream;
        try
        {
            while (!ct.IsCancellationRequested && DateTimeOffset.UtcNow < deadline)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                wait.CancelAfter(Heartbeat);
                string message;
                try
                {
                    var collection = await subscription.Reader.ReadAsync(wait.Token);
                    message = $"event: change\ndata: {new JsonObject { ["collection"] = collection }.ToJsonString()}\n\n";
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    message = ": heartbeat\n\n";
                }
                await context.Response.WriteAsync(message, ct);
                await context.Response.Body.FlushAsync(ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // the page went away
        }
    }
}

public static class ArtifactNegotiateEndpoint
{
    /// <summary>GET /events/negotiate: {"url": "wss://…"}, a Web PubSub client URL for this caller that joins the
    /// instance's group and may only receive. Same access check as /events. 404 when Web PubSub isn't configured (the
    /// page then uses /events); 503 when it couldn't be reached (the page retries).</summary>
    public static async Task<IResult> Handle(HttpContext context)
    {
        var viewer = ArtifactViewer.From(context.User);
        if (!ArtifactEventsEndpoint.MayListen(viewer) || viewer.Id is null) return Results.StatusCode(StatusCodes.Status403Forbidden);
        if (ArtifactPubSub.Shared is not { } pubsub) return Results.NotFound();

        context.Response.Headers.CacheControl = "no-store"; // the URL carries a token
        try
        {
            var url = await pubsub.ClientUrlAsync(viewer.Id, context.RequestAborted);
            return Results.Json(new { url = url.AbsoluteUri });
        }
        catch (Exception e) when (!context.RequestAborted.IsCancellationRequested)
        {
            context.RequestServices.GetService<ILoggerFactory>()?.CreateLogger(typeof(ArtifactNegotiateEndpoint))
                .LogError(e, "Getting a Web PubSub client URL failed");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }
}
