using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AzureCosmosDB.MCP.Toolkit.Artifact;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AzureCosmosDB.MCP.Toolkit.Tests;

public class ArtifactQueryTests
{
    private static ArtifactRecord Doc(string id, string json) =>
        new($"ideas/{id}", id, JsonNode.Parse(json)!.AsObject(), 1, null);

    private static readonly ArtifactRecord[] Docs =
    [
        Doc("a", """{ "votes": 3, "tags": ["x"], "by": "u1" }"""),
        Doc("b", """{ "votes": 7, "tags": ["y"], "by": "u2" }"""),
        Doc("c", """{ "tags": ["x", "y"], "by": "u1" }"""),
    ];

    private static List<string> Ids(string? where = null, string? orderBy = null, int? limit = null) =>
        ArtifactQuery.Run(Docs, ArtifactQuery.Check(where is null ? null : JsonNode.Parse(where), orderBy is null ? null : JsonNode.Parse(orderBy), limit))
            .Select(r => r.Id).ToList();

    [Fact]
    public void Filters_on_top_level_fields() =>
        Ids("""[{ "field": "by", "op": "==", "value": "u1" }]""").Should().Equal("a", "c");

    [Fact]
    public void Array_contains_and_in() =>
        Ids("""[{ "field": "tags", "op": "array-contains", "value": "y" }, { "field": "by", "op": "in", "value": ["u1"] }]""").Should().Equal("c");

    [Fact]
    public void Orders_with_missing_fields_last_and_limits()
    {
        Ids(orderBy: """{ "field": "votes", "dir": "desc" }""").Should().Equal("b", "a", "c");
        Ids(orderBy: """{ "field": "votes" }""", limit: 1).Should().Equal("a");
    }

    [Fact]
    public void Range_filters_only_match_the_same_type() =>
        Ids("""[{ "field": "votes", "op": ">", "value": "1" }]""").Should().BeEmpty();

    [Fact]
    public void Bad_queries_are_refused()
    {
        var act = () => ArtifactQuery.Check(JsonNode.Parse("""[{ "field": "a", "op": "like", "value": 1 }]"""), null, null);
        act.Should().Throw<ArtifactDbException>().Which.Code.Should().Be("invalid_argument");
        ((Action)(() => ArtifactQuery.Check(null, null, 0))).Should().Throw<ArtifactDbException>();
    }

    [Fact]
    public void Update_merges_objects_and_replaces_arrays()
    {
        var merged = ArtifactQuery.DeepMerge(
            JsonNode.Parse("""{ "a": { "x": 1, "y": 2 }, "list": [1, 2], "keep": true }""")!.AsObject(),
            JsonNode.Parse("""{ "a": { "y": 3 }, "list": [9] }""")!.AsObject());
        JsonNode.DeepEquals(merged, JsonNode.Parse("""{ "a": { "x": 1, "y": 3 }, "list": [9], "keep": true }""")).Should().BeTrue();
    }
}

public class ArtifactPathsTests
{
    [Theory]
    [InlineData("ideas")]
    [InlineData("ideas/a/b")]
    [InlineData("ideas//a")]
    [InlineData("ideas/..")]
    [InlineData("ideas/a b")]
    public void Document_paths_need_valid_even_segments(string path)
    {
        var act = () => ArtifactPaths.Document(path);
        act.Should().Throw<ArtifactDbException>();
    }

    [Fact]
    public void Bodies_must_be_objects()
    {
        ((Action)(() => ArtifactPaths.CheckBody(JsonNode.Parse("[1]")))).Should().Throw<ArtifactDbException>();
        ArtifactPaths.CheckBody(JsonNode.Parse("""{ "a": 1 }""")).Should().NotBeNull();
    }
}

[Collection("Environment variables")] // these tests set process-wide settings, so they run one at a time
public class ArtifactViewerTests
{
    private static ClaimsPrincipal User(string oid, params string[] roles) =>
        new(new ClaimsIdentity([new Claim("oid", oid), .. roles.Select(r => new Claim("roles", r))], "Bearer"));

    [Fact]
    public void Levels_come_from_app_roles_and_the_owner_id()
    {
        Environment.SetEnvironmentVariable("ARTIFACT_OWNER_ID", "owner-oid");
        ArtifactViewer.From(User("owner-oid")).Level.Should().Be("owner");
        ArtifactViewer.From(User("u1", "Mcp.Tool.Executor", "Cosmos.Admin")).Level.Should().Be("admin");
        ArtifactViewer.From(User("u1", "Cosmos.Write")).Level.Should().Be("interact");
        ArtifactViewer.From(User("u1", "Cosmos.Read")).Level.Should().Be("view");
        ArtifactViewer.From(User("u1", "Mcp.Tool.Executor")).Level.Should().BeNull();
        ArtifactViewer.From(new ClaimsPrincipal(new ClaimsIdentity())).Level.Should().BeNull();
    }

    [Fact]
    public void Levels_come_from_the_highest_cosmos_access_role()
    {
        try
        {
            Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", """
                [{ "users": ["Jane@Example.com", "U2"], "role": "view", "containers": ["docs"] },
                 { "users": ["jane@example.com"], "role": "interact", "containers": ["votes"] },
                 { "users": ["u3"], "role": "owner", "containers": ["*"] }]
                """);
            var jane = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "u1"), new Claim("preferred_username", "jane@example.com")], "Bearer"));
            ArtifactViewer.From(jane).Level.Should().Be("interact");
            ArtifactViewer.From(User("u2")).Level.Should().Be("view");                  // by object ID
            ArtifactViewer.From(User("u3")).Level.Should().BeNull();                    // not a cosmos.access role
            ArtifactViewer.From(User("u4")).Level.Should().BeNull();                    // not listed
            ArtifactViewer.From(User("u4", "Cosmos.Read")).Level.Should().Be("view");   // app roles still count
            Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", "not json");
            ArtifactViewer.From(jane).Level.Should().BeNull();
        }
        finally
        {
            Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", null);
        }
    }
}

/// <summary>The artifact tools over /mcp, without Cosmos DB: the test caller is anonymous, so it has no level.</summary>
[Collection("Environment variables")]
public class ArtifactDbToolsMcpTests : IClassFixture<McpTestApplicationFactory>
{
    private readonly HttpClient _client;

    public ArtifactDbToolsMcpTests(McpTestApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private async Task<JsonNode> Rpc(string method, object? @params = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method, @params }), Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        var response = await _client.SendAsync(request);
        response.IsSuccessStatusCode.Should().BeTrue(await response.Content.ReadAsStringAsync());
        var text = await response.Content.ReadAsStringAsync();
        var json = text.TrimStart().StartsWith('{')
            ? text
            : text.Split('\n').First(l => l.StartsWith("data:"))["data:".Length..];
        return JsonNode.Parse(json)!["result"]!;
    }

    private Task<JsonNode> Call(string name, object arguments) => Rpc("tools/call", new { name, arguments });

    [Fact]
    public async Task Lists_only_the_artifact_database_tools()
    {
        var tools = (await Rpc("tools/list"))["tools"]!.AsArray().Select(t => t!["name"]!.GetValue<string>());
        tools.Should().BeEquivalentTo("db_get", "db_query", "db_set", "db_update", "db_delete");
    }

    [Theory]
    [InlineData("db_get")]
    [InlineData("db_query")]
    [InlineData("db_set")]
    [InlineData("db_delete")]
    public async Task Calls_from_someone_not_signed_in_are_unauthenticated(string tool)
    {
        var result = await Call(tool, new { path = "ideas/i1", collection = "ideas", data = new { text = "hi" } });
        result["isError"]!.GetValue<bool>().Should().BeTrue();
        result["content"]![0]!["text"]!.GetValue<string>().Should().StartWith("unauthenticated: ");
    }

    [Theory]
    [InlineData("POST", "/api/mcp/tools/list_databases")]
    [InlineData("GET", "/api/mcp/tools")]
    [InlineData("POST", "/mcp/http")]
    [InlineData("GET", "/index.html")]
    public async Task The_toolkits_tester_is_not_served(string method, string path)
    {
        var response = await _client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path)
        {
            Content = method == "POST" ? new StringContent("{}", Encoding.UTF8, "application/json") : null,
        });
        ((int)response.StatusCode).Should().BeOneOf(404, 405);
    }

    [Fact]
    public async Task Events_refuse_callers_without_a_level()
    {
        var response = await _client.GetAsync("/events");
        ((int)response.StatusCode).Should().Be(403);
    }

    [Fact]
    public async Task Negotiate_refuses_callers_without_a_level()
    {
        var response = await _client.GetAsync("/events/negotiate");
        ((int)response.StatusCode).Should().Be(403);
    }

}

[Collection("Environment variables")] // these tests set process-wide settings, so they run one at a time
public class ArtifactEventsTests
{
    [Fact]
    public async Task Subscribers_hear_published_collections_until_they_leave()
    {
        var events = new ArtifactEvents(() => throw new InvalidOperationException("no Cosmos in this test"));
        using (var subscription = events.Subscribe(readChangeFeed: false))
        {
            events.Publish("ideas");
            (await subscription.Reader.ReadAsync()).Should().Be("ideas");
            events.SubscriberCount.Should().Be(1);
        }
        events.SubscriberCount.Should().Be(0);
    }

    [Fact]
    public async Task Events_stream_changes_to_callers_with_a_level()
    {
        Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", """[{"users":["u1"],"role":"view","containers":["docs"]}]""");
        try
        {
            var context = new Microsoft.AspNetCore.Http.DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "u1")], "Bearer")),
                RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
            };
            var body = new MemoryStream();
            context.Response.Body = body;
            using var cts = new CancellationTokenSource();
            context.RequestAborted = cts.Token;

            var handler = ArtifactEventsEndpoint.Handle(context);
            for (var i = 0; i < 50 && ArtifactEvents.Shared.SubscriberCount == 0; i++) await Task.Delay(20);
            ArtifactEvents.Shared.Publish("ideas");
            for (var i = 0; i < 50 && !Encoding.UTF8.GetString(body.ToArray()).Contains("event: change"); i++) await Task.Delay(20);
            cts.Cancel();
            await handler;

            context.Response.StatusCode.Should().Be(200);
            context.Response.ContentType.Should().Be("text/event-stream");
            Encoding.UTF8.GetString(body.ToArray()).Should().Contain("event: change\ndata: {\"collection\":\"ideas\"}");
        }
        finally
        {
            Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", null);
        }
    }

    private sealed class FakePubSub(bool fail = false) : IArtifactPubSub
    {
        public List<string> Users { get; } = [];
        public List<string> Published { get; } = [];

        public Task<Uri> ClientUrlAsync(string userId, CancellationToken cancellationToken)
        {
            Users.Add(userId);
            return Task.FromResult(new Uri("wss://wps.example/client/hubs/artifact?access_token=t"));
        }

        public Task PublishAsync(string collection, CancellationToken cancellationToken)
        {
            if (fail) throw new InvalidOperationException("Web PubSub is down");
            Published.Add(collection);
            return Task.CompletedTask;
        }
    }

    private static Microsoft.AspNetCore.Http.DefaultHttpContext ViewerContext() => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "u1")], "Bearer")),
        RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
        Response = { Body = new MemoryStream() },
    };

    private static async Task WithViewerLevel(IArtifactPubSub? pubsub, Func<Task> test)
    {
        var saved = ArtifactPubSub.Shared;
        Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", """[{"users":["u1"],"role":"view","containers":["docs"]}]""");
        ArtifactPubSub.Shared = pubsub;
        try { await test(); }
        finally
        {
            ArtifactPubSub.Shared = saved;
            Environment.SetEnvironmentVariable("ARTIFACT_COSMOS_ACCESS", null);
        }
    }

    [Fact]
    public Task Negotiate_is_not_found_without_web_pubsub() => WithViewerLevel(null, async () =>
    {
        var context = ViewerContext();
        await (await ArtifactNegotiateEndpoint.Handle(context)).ExecuteAsync(context);
        context.Response.StatusCode.Should().Be(404);
    });

    [Fact]
    public Task Negotiate_gives_callers_with_a_level_a_client_url() => WithViewerLevel(new FakePubSub(), async () =>
    {
        var context = ViewerContext();
        await (await ArtifactNegotiateEndpoint.Handle(context)).ExecuteAsync(context);

        context.Response.StatusCode.Should().Be(200);
        context.Response.Headers.CacheControl.ToString().Should().Be("no-store");
        var body = JsonNode.Parse(Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray()))!;
        body["url"]!.GetValue<string>().Should().Be("wss://wps.example/client/hubs/artifact?access_token=t");
        ((FakePubSub)ArtifactPubSub.Shared!).Users.Should().Equal(ArtifactViewer.From(context.User).Id);
    });

    [Fact]
    public Task Writes_are_published_to_web_pubsub_and_local_subscribers() => WithViewerLevel(new FakePubSub(), async () =>
    {
        using var subscription = ArtifactEvents.Shared.Subscribe(readChangeFeed: false);
        await ArtifactDbTools.Changed("ideas/i1", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        ((FakePubSub)ArtifactPubSub.Shared!).Published.Should().Equal("ideas");
        (await subscription.Reader.ReadAsync()).Should().Be("ideas");
    });

    [Fact]
    public Task A_failing_web_pubsub_doesnt_fail_the_write() => WithViewerLevel(new FakePubSub(fail: true), async () =>
    {
        using var subscription = ArtifactEvents.Shared.Subscribe(readChangeFeed: false);
        var changed = () => ArtifactDbTools.Changed("ideas/i1", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        await changed.Should().NotThrowAsync();
        (await subscription.Reader.ReadAsync()).Should().Be("ideas");
    });
}

/// <summary>The server with Entra authentication on, as deployed: how MCP clients such as Claude discover sign-in.</summary>
public sealed class AuthEnabledApplicationFactory : Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>
{
    public const string TenantId = "11111111-1111-1111-1111-111111111111";
    public const string ClientId = "22222222-2222-2222-2222-222222222222";

    // Program.cs reads these as it starts, before ConfigureWebHost runs, so set them when the factory is created.
    public AuthEnabledApplicationFactory()
    {
        Environment.SetEnvironmentVariable("DEV_BYPASS_AUTH", "false");
        Environment.SetEnvironmentVariable("DevelopmentMode__BypassAuthentication", "false"); // overrides appsettings.Development.json
        Environment.SetEnvironmentVariable("AzureAd__TenantId", TenantId);
        Environment.SetEnvironmentVariable("AzureAd__ClientId", ClientId);
    }

    protected override void Dispose(bool disposing)
    {
        Environment.SetEnvironmentVariable("AzureAd__TenantId", null);
        Environment.SetEnvironmentVariable("AzureAd__ClientId", null);
        Environment.SetEnvironmentVariable("DevelopmentMode__BypassAuthentication", null);
        Environment.SetEnvironmentVariable("DEV_BYPASS_AUTH", "true");
        base.Dispose(disposing);
    }
}

[Collection("Environment variables")]
public class OAuthDiscoveryTests : IClassFixture<AuthEnabledApplicationFactory>
{
    private readonly HttpClient _client;

    public OAuthDiscoveryTests(AuthEnabledApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Authorization_server_metadata_points_at_entra()
    {
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");
        response.IsSuccessStatusCode.Should().BeTrue();
        var metadata = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        var entra = $"https://login.microsoftonline.com/{AuthEnabledApplicationFactory.TenantId}";
        metadata["authorization_endpoint"]!.GetValue<string>().Should().Be($"{entra}/oauth2/v2.0/authorize");
        metadata["token_endpoint"]!.GetValue<string>().Should().Be($"{entra}/oauth2/v2.0/token");
        metadata["code_challenge_methods_supported"]!.AsArray().Select(m => m!.GetValue<string>()).Should().Contain("S256");
        metadata["scopes_supported"]!.AsArray().Select(m => m!.GetValue<string>())
            .Should().Contain($"{AuthEnabledApplicationFactory.ClientId}/.default");
        metadata["registration_endpoint"].Should().BeNull();
    }

    [Theory]
    [InlineData("/.well-known/oauth-protected-resource")]
    [InlineData("/.well-known/oauth-protected-resource/mcp")]
    public async Task No_protected_resource_metadata_so_clients_send_no_resource_parameter(string path)
    {
        ((int)(await _client.GetAsync(path)).StatusCode).Should().Be(404);
    }

    [Fact]
    public async Task Calls_without_a_token_are_told_the_scope()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        var response = await _client.SendAsync(request);
        ((int)response.StatusCode).Should().Be(401);
        var challenge = response.Headers.WwwAuthenticate.ToString();
        challenge.Should().StartWith("Bearer").And.Contain($"scope=\"{AuthEnabledApplicationFactory.ClientId}/.default offline_access\"");
        challenge.Should().NotContain("resource_metadata");
    }
}

/// <summary>The artifact's page: tickets from the Static Web App's "ticket" function, signed with TICKET_SECRET.</summary>
[Collection("Environment variables")]
public class TicketAuthenticationTests : IClassFixture<AuthEnabledApplicationFactory>
{
    private const string Secret = "test-secret";
    private const string Audience = "mcp.example.net";
    private readonly HttpClient _client;

    public TicketAuthenticationTests(AuthEnabledApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    // What the function in src/runtime/api/ticket makes.
    private static string Ticket(string email, string secret = Secret, string aud = Audience, int lifetime = 60, int age = 0)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - age;
        var payload = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { sub = email, aud, iat = now, exp = now + lifetime })));
        var signature = System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.ASCII.GetBytes(payload));
        return payload + "." + Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(signature);
    }

    private static ArtifactViewer Viewer(string email) =>
        ArtifactViewer.From(TicketAuthenticationHandler.Validate(Ticket(email), DateTimeOffset.UtcNow));

    private static void WithSettings(Dictionary<string, string?> settings, Action test)
    {
        var all = new Dictionary<string, string?>(settings) { ["TICKET_SECRET"] = Secret, ["TICKET_AUDIENCE"] = Audience };
        foreach (var (k, v) in all) Environment.SetEnvironmentVariable(k, v);
        try { test(); }
        finally { foreach (var k in all.Keys) Environment.SetEnvironmentVariable(k, null); }
    }

    private static async Task WithSettingsAsync(Func<Task> test)
    {
        Environment.SetEnvironmentVariable("TICKET_SECRET", Secret);
        Environment.SetEnvironmentVariable("TICKET_AUDIENCE", Audience);
        Environment.SetEnvironmentVariable("ARTIFACT_OWNER_EMAIL", "owner@example.com");
        try { await test(); }
        finally
        {
            foreach (var k in new[] { "TICKET_SECRET", "TICKET_AUDIENCE", "ARTIFACT_OWNER_EMAIL" }) Environment.SetEnvironmentVariable(k, null);
        }
    }

    [Fact]
    public void Only_genuine_current_tickets_for_this_server_are_accepted() => WithSettings(new(), () =>
    {
        var now = DateTimeOffset.UtcNow;
        TicketAuthenticationHandler.Validate(Ticket("Jane.Doe@Example.com"), now)!
            .FindFirst("email")!.Value.Should().Be("jane.doe@example.com");
        TicketAuthenticationHandler.Validate(Ticket("jane@example.com", secret: "wrong"), now).Should().BeNull();
        TicketAuthenticationHandler.Validate(Ticket("jane@example.com", aud: "other.example.net"), now).Should().BeNull();
        TicketAuthenticationHandler.Validate(Ticket("jane@example.com", age: 120), now).Should().BeNull();       // expired
        TicketAuthenticationHandler.Validate(Ticket("jane@example.com", lifetime: 3600), now).Should().BeNull(); // too long
        TicketAuthenticationHandler.Validate(Ticket("janedoe"), now).Should().BeNull();
        TicketAuthenticationHandler.Validate("not.a ticket", now).Should().BeNull();

        // A changed email breaks the signature.
        var parts = Ticket("jane@example.com").Split('.');
        var forged = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(parts[0])).Replace("jane@", "owner@")));
        TicketAuthenticationHandler.Validate(forged + "." + parts[1], now).Should().BeNull();
    });

    [Fact]
    public void Tickets_from_the_function_are_accepted() => WithSettings(new(), () =>
    {
        // Made by src/runtime/api/ticket/index.js with TICKET_SECRET=test-secret, TICKET_AUDIENCE=mcp.example.net
        const string fromFunction ="eyJzdWIiOiJqYW5lLmRvZUBleGFtcGxlLmNvbSIsImF1ZCI6Im1jcC5leGFtcGxlLm5ldCIsImlhdCI6MTc5NDgyNDM2MiwiZXhwIjoxNzk0ODI0NDIyfQ"
            + ".EHbs5jhqtbeXuR7Y5AnKSgVMcgQKWiZqkGT--K_3iB4";
        var issued = DateTimeOffset.FromUnixTimeSeconds(1794824362);
        TicketAuthenticationHandler.Validate(fromFunction, issued.AddSeconds(30))!
            .FindFirst("email")!.Value.Should().Be("jane.doe@example.com");
        TicketAuthenticationHandler.Validate(fromFunction, issued.AddMinutes(5)).Should().BeNull();
    });

    [Fact]
    public void Without_a_secret_no_ticket_is_accepted()
    {
        TicketAuthenticationHandler.Validate(Ticket("jane@example.com"), DateTimeOffset.UtcNow).Should().BeNull();
    }

    [Fact]
    public void The_previous_secret_still_works_while_changing_secrets() => WithSettings(new()
    {
        ["TICKET_SECRET_PREVIOUS"] = "old-secret",
    }, () =>
    {
        TicketAuthenticationHandler.Validate(Ticket("jane@example.com", secret: "old-secret"), DateTimeOffset.UtcNow).Should().NotBeNull();
    });

    [Fact]
    public void Levels_come_from_the_owner_email_and_cosmos_access() => WithSettings(new()
    {
        ["ARTIFACT_OWNER_EMAIL"] = "Owner@Example.com",
        ["ARTIFACT_COSMOS_ACCESS"] = """
            [{"users":["ed@example.com"],"role":"admin","containers":["*"]},
             {"users":["Con@Example.com"],"role":"interact","containers":["docs"]},
             {"users":["vi@other.org"],"role":"view","containers":["docs"]}]
            """,
    }, () =>
    {
        var owner = Viewer("owner@example.com");
        owner.Level.Should().Be("owner");
        owner.Id.Should().Be("owner@example.com");
        owner.Name.Should().Be("Owner");
        Viewer("ed@example.com").Level.Should().Be("admin");
        Viewer("con@example.com").Level.Should().Be("interact");
        Viewer("vi@other.org").Level.Should().Be("view");
        Viewer("someone@example.com").Level.Should().BeNull();
        Viewer("jane.doe@example.com").Name.Should().Be("Jane Doe");
    });

    [Fact]
    public void Entra_tokens_are_identified_by_email_too() => WithSettings(new()
    {
        ["ARTIFACT_COSMOS_ACCESS"] = """[{"users":["jane@example.com"],"role":"interact","containers":["docs"]}]""",
    }, () =>
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("oid", "u1"), new Claim("preferred_username", "Jane@Example.com"), new Claim("name", "Jane")], "Bearer"));
        var viewer = ArtifactViewer.From(user);
        viewer.Id.Should().Be("jane@example.com");
        viewer.Level.Should().Be("interact");
        viewer.Name.Should().Be("Jane");
    });

    private Task<HttpResponseMessage> Get(string path, string? ticket)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (ticket is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ticket);
        return _client.SendAsync(request);
    }

    [Fact]
    public async Task Me_answers_for_the_person_in_the_ticket() => await WithSettingsAsync(async () =>
    {
        var response = await Get("/me", Ticket("owner@example.com"));
        response.IsSuccessStatusCode.Should().BeTrue();
        var me = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
        me["id"]!.GetValue<string>().Should().Be("owner@example.com");
        me["level"]!.GetValue<string>().Should().Be("owner");
    });

    [Fact]
    public async Task Bad_tickets_and_the_old_header_are_refused() => await WithSettingsAsync(async () =>
    {
        ((int)(await Get("/me", Ticket("owner@example.com", secret: "wrong"))).StatusCode).Should().Be(401);
        ((int)(await Get("/me", null)).StatusCode).Should().Be(401);

        var header = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            """{"identityProvider":"aad","userId":"x","userDetails":"owner@example.com","userRoles":["authenticated"]}"""));
        foreach (var path in new[] { "/me", "/api/me" })
        {
            var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Add("x-ms-client-principal", header);
            ((int)(await _client.SendAsync(request)).StatusCode).Should().BeOneOf(401, 404);
        }
    });

    [Fact]
    public async Task Calls_without_a_ticket_still_tell_claude_the_scope() => await WithSettingsAsync(async () =>
    {
        var response = await Get("/me", null);
        response.Headers.WwwAuthenticate.ToString().Should().Contain("scope=");
    });

    [Fact]
    public async Task Someone_signed_in_but_not_in_cosmos_access_is_refused_before_cosmos_db() => await WithSettingsAsync(async () =>
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0", id = 1, method = "tools/call",
                @params = new { name = "db_get", arguments = new { path = "ideas/i1" } },
            }), Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Ticket("stranger@example.com"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        var text = await (await _client.SendAsync(request)).Content.ReadAsStringAsync();
        var json = text.TrimStart().StartsWith('{') ? text : text.Split('\n').First(l => l.StartsWith("data:"))["data:".Length..];
        var result = JsonNode.Parse(json)!["result"]!;
        result["isError"]!.GetValue<bool>().Should().BeTrue();
        result["content"]![0]!["text"]!.GetValue<string>().Should().StartWith("permission_denied: ");
    });
}
