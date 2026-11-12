// Pushes "this collection changed" to the artifact's open pages, so their db listeners refresh at once instead of
// polling. Pages subscribe through GET /events (server-sent events); each message names a collection, never data,
// and the page re-reads through db_query, so the artifact's rules still decide what it sees.
//
// Changes come from two places:
//   - Cosmos DB's change feed (latest-version mode, from "now"), read every second while anyone is subscribed and
//     stopped a minute after the last one leaves. It reports creates and updates made through any replica.
//   - This replica's own writes (db_set, db_update, db_delete), published at once. The change feed doesn't report
//     deletes, so a delete made through another replica reaches pages through their fallback polling.
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.Azure.Cosmos;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed class ArtifactEvents
{
    public static ArtifactEvents Shared { get; } = new(() => ArtifactStore.Shared.Docs);

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan IdleStop = TimeSpan.FromMinutes(1);

    private readonly Func<Container> _container;
    private readonly ConcurrentDictionary<Guid, Channel<string>> _subscribers = new();
    private readonly object _gate = new();
    private Task? _feed;

    public ArtifactEvents(Func<Container> container)
    {
        _container = container;
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

    private async Task ReadChangeFeedAsync()
    {
        var idleSince = DateTimeOffset.UtcNow;
        FeedIterator? iterator = null;
        string? continuation = null;
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

            try
            {
                iterator ??= _container().GetChangeFeedStreamIterator(
                    continuation is null ? ChangeFeedStartFrom.Now() : ChangeFeedStartFrom.ContinuationToken(continuation),
                    ChangeFeedMode.LatestVersion,
                    new ChangeFeedRequestOptions { PageSizeHint = 100 });
                using var page = await iterator.ReadNextAsync();
                continuation = page.ContinuationToken ?? continuation;
                if (page.StatusCode == HttpStatusCode.NotModified)
                {
                    await Task.Delay(PollInterval);
                    continue;
                }
                page.EnsureSuccessStatusCode();
                var body = await JsonNode.ParseAsync(page.Content);
                var collections = (body?["Documents"]?.AsArray() ?? [])
                    .Select(d => d?["collection"]?.GetValue<string>())
                    .Where(c => !string.IsNullOrEmpty(c))
                    .Distinct();
                foreach (var c in collections) Publish(c!);
            }
            catch (Exception e)
            {
                Logger?.LogWarning(e, "Reading the artifact change feed failed; retrying");
                iterator = null;
                await Task.Delay(TimeSpan.FromSeconds(5));
            }
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

    /// <summary>GET /events: server-sent events, one "change" per changed collection, for callers with a level.</summary>
    public static async Task Handle(HttpContext context)
    {
        var viewer = ArtifactViewer.From(context.User);
        if (viewer.Level is null)
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
        try
        {
            while (!ct.IsCancellationRequested)
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
