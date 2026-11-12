using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AzureCosmosDB.MCP.Toolkit.Artifact;
using FluentAssertions;
using Xunit;

namespace AzureCosmosDB.MCP.Toolkit.Tests;

public class ArtifactRulesTests
{
    // The Ideas board's rules: everyone reads votes, each person writes only their own votes/<id>.
    private static readonly IReadOnlyList<ArtifactRule> IdeasBoard = ArtifactRules.Validate(JsonNode.Parse("""
        [{ "path": "votes", "read": "view", "write": "owner" }, { "path": "votes/{self}", "write": "interact" }]
        """));

    private static bool Can(string path, string action, string id, string level) =>
        ArtifactRules.CanAccess(IdeasBoard, path, action, new ArtifactViewer(id, level));

    [Fact]
    public void Contributors_write_their_own_votes_only()
    {
        Can("votes/u1", "write", "u1", "interact").Should().BeTrue();
        Can("votes/u2", "write", "u1", "interact").Should().BeFalse();
        Can("votes/u2", "write", "u1", "owner").Should().BeTrue();
    }

    [Fact]
    public void Viewers_read_everything_but_write_nothing()
    {
        Can("votes/u2", "read", "u1", "view").Should().BeTrue();
        Can("ideas/i1", "read", "u1", "view").Should().BeTrue();
        Can("ideas/i1", "write", "u1", "view").Should().BeFalse();
        Can("votes/u1", "write", "u1", "view").Should().BeFalse();
    }

    [Fact]
    public void Root_defaults_let_contributors_add_ideas()
    {
        Can("ideas/i1", "write", "u1", "interact").Should().BeTrue();
    }

    [Fact]
    public void Users_subtrees_are_private_by_default()
    {
        Can("data/users/u1/notes/n1", "read", "u1", "view").Should().BeTrue();
        Can("data/users/u2/notes/n1", "read", "u1", "admin").Should().BeFalse();
    }

    [Fact]
    public void Callers_without_a_level_can_do_nothing()
    {
        ArtifactRules.CanAccess(IdeasBoard, "ideas/i1", "read", new ArtifactViewer("u1", null)).Should().BeFalse();
    }

    [Theory]
    [InlineData("""[{ "path": "a", "read": "admin", "write": "view" }]""", "write is below read")]
    [InlineData("""[{ "path": "a/{self}/b" }]""", "must be the last segment")]
    [InlineData("""[{ "path": "a", "read": "boss" }]""", "must be one of")]
    [InlineData("""[{ "path": "a" }, { "path": "a/" }]""", "two rules")]
    public void Invalid_rules_are_refused(string rules, string message)
    {
        var act = () => ArtifactRules.Validate(JsonNode.Parse(rules));
        act.Should().Throw<ArtifactDbException>().WithMessage($"*{message}*");
    }
}

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
    public void Signed_in_callers_without_a_role_get_the_default_level()
    {
        try
        {
            Environment.SetEnvironmentVariable("ARTIFACT_DEFAULT_LEVEL", "interact");
            ArtifactViewer.From(User("u1")).Level.Should().Be("interact");
            ArtifactViewer.From(User("u1", "Cosmos.Read")).Level.Should().Be("view");
            ArtifactViewer.From(new ClaimsPrincipal(new ClaimsIdentity())).Level.Should().BeNull();
            Environment.SetEnvironmentVariable("ARTIFACT_DEFAULT_LEVEL", "owner");
            ArtifactViewer.From(User("u1")).Level.Should().BeNull();
        }
        finally
        {
            Environment.SetEnvironmentVariable("ARTIFACT_DEFAULT_LEVEL", null);
        }
    }
}

/// <summary>The artifact tools over /mcp, without Cosmos DB: the test caller is anonymous, so it has no level.</summary>
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

    [Fact]
    public async Task An_unreadable_document_looks_absent()
    {
        var result = await Call("db_get", new { path = "ideas/i1" });
        result["isError"]?.GetValue<bool>().Should().NotBe(true);
        result["structuredContent"]!["exists"]!.GetValue<bool>().Should().BeFalse();
    }

    [Fact]
    public async Task A_write_without_a_level_is_refused()
    {
        var result = await Call("db_set", new { path = "ideas/i1", data = new { text = "hi" } });
        result["isError"]!.GetValue<bool>().Should().BeTrue();
        result["content"]![0]!["text"]!.GetValue<string>().Should().StartWith("invalid_argument: ");
    }

    [Fact]
    public async Task Bad_paths_are_invalid_arguments()
    {
        var result = await Call("db_get", new { path = "ideas" });
        result["isError"]!.GetValue<bool>().Should().BeTrue();
        result["content"]![0]!["text"]!.GetValue<string>().Should().StartWith("invalid_argument: a document path");
    }
}
