using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AzureCosmosDB.MCP.Toolkit.Artifact;
using FluentAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace AzureCosmosDB.MCP.Toolkit.Tests;

/// <summary>Token passthrough (test only): the caller's own Cosmos DB token, and which container each collection is in.</summary>
[Collection("Environment variables")] // these tests set process-wide settings, so they run one at a time
public class CosmosTokenPassthroughTests
{
    private const string Tenant = "11111111-1111-1111-1111-111111111111";
    private const string Endpoint = "https://cosmos-alz-test.documents.azure.com:443/";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    // What az account get-access-token gives, unsigned: Cosmos DB checks signatures, the server doesn't.
    private static string Token(
        string upn = "jane.doe@example.com", string tid = Tenant, string aud = "https://cosmos.azure.com", int expiresIn = 3600)
    {
        string Part(object o) => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(o)));
        return Part(new { alg = "RS256", typ = "JWT" }) + "." +
            Part(new { aud, tid, upn, exp = Now.ToUnixTimeSeconds() + expiresIn }) + ".c2lnbmF0dXJl";
    }

    private static void WithSettings(Dictionary<string, string?> settings, Action test)
    {
        foreach (var (k, v) in settings) Environment.SetEnvironmentVariable(k, v);
        try
        {
            test();
        }
        finally
        {
            foreach (var k in settings.Keys) Environment.SetEnvironmentVariable(k, null);
        }
    }

    private static void WithTenant(Action test) =>
        WithSettings(new() { ["AzureAd__TenantId"] = Tenant, ["COSMOS_ENDPOINT"] = Endpoint }, test);

    private static Action Checking(string? token, string? email = "jane.doe@example.com") =>
        () => CosmosTokenPassthrough.Check(token, email, Now);

    [Fact]
    public void A_callers_own_current_cosmos_token_is_accepted() => WithTenant(() =>
    {
        var claims = CosmosTokenPassthrough.Check(Token(), "Jane.Doe@example.com", Now);
        claims.Email.Should().Be("jane.doe@example.com");
        claims.Expires.Should().BeCloseTo(Now.AddHours(1), TimeSpan.FromSeconds(2));
        // The account's own endpoint is a Cosmos DB audience too, with or without the port and slash.
        CosmosTokenPassthrough.Check(Token(aud: "https://cosmos-alz-test.documents.azure.com"), "jane.doe@example.com", Now)
            .Should().NotBeNull();
        CosmosTokenPassthrough.Check(Token(aud: Endpoint), "jane.doe@example.com", Now).Should().NotBeNull();
    });

    [Fact]
    public void Someone_elses_token_is_refused() => WithTenant(() =>
        Checking(Token(upn: "john.smith@example.com")).Should().Throw<ArtifactDbException>()
            .Where(e => e.Code == "unauthenticated").WithMessage("*someone else's*"));

    [Fact]
    public void A_token_from_another_tenant_is_refused() => WithTenant(() =>
        Checking(Token(tid: "99999999-9999-9999-9999-999999999999")).Should().Throw<ArtifactDbException>()
            .Where(e => e.Code == "unauthenticated").WithMessage("*another tenant*"));

    [Fact]
    public void An_expired_token_is_refused() => WithTenant(() =>
        Checking(Token(expiresIn: -60)).Should().Throw<ArtifactDbException>()
            .Where(e => e.Code == "unauthenticated").WithMessage("*expired*"));

    [Theory]
    [InlineData("https://management.azure.com")]
    [InlineData("https://other-account.documents.azure.com")]
    [InlineData("api://22222222-2222-2222-2222-222222222222")]
    public void A_token_for_something_else_is_refused(string aud) => WithTenant(() =>
        Checking(Token(aud: aud)).Should().Throw<ArtifactDbException>()
            .Where(e => e.Code == "unauthenticated").WithMessage("*isn't for Cosmos DB*"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("a.b.c")]
    public void No_token_or_a_malformed_one_is_refused(string? token) => WithTenant(() =>
        Checking(token).Should().Throw<ArtifactDbException>().Where(e => e.Code == "unauthenticated"));

    [Fact]
    public void A_caller_who_isnt_signed_in_is_refused() => WithTenant(() =>
        Checking(Token(), email: null).Should().Throw<ArtifactDbException>().Where(e => e.Code == "unauthenticated"));

    [Fact]
    public void Top_level_collections_named_in_artifact_containers_have_their_own() =>
        WithSettings(new() { ["ARTIFACT_CONTAINERS"] = """["votes", "finance"]""" }, () =>
        {
            ArtifactStore.ContainerName("votes").Should().Be("votes");
            ArtifactStore.ContainerName("votes/jane.doe@example.com").Should().Be("votes");
            ArtifactStore.ContainerName("finance/q1/lines/l1").Should().Be("finance");
            ArtifactStore.ContainerName("ideas/i1").Should().Be("docs");
            ArtifactStore.ContainerName("data/votes/x").Should().Be("docs"); // only the first segment counts
            ArtifactStore.ContainerName("votesx").Should().Be("docs");
        });

    [Fact]
    public void Without_artifact_containers_everything_is_in_docs()
    {
        ArtifactStore.ContainerName("votes/u1").Should().Be("docs");
        WithSettings(new() { ["ARTIFACT_CONTAINERS"] = "not json" }, () =>
            ArtifactStore.ContainerName("votes/u1").Should().Be("docs"));
    }

    [Fact]
    public void Cosmos_refusals_become_permission_denied_and_unauthenticated()
    {
        var denied = ArtifactStore.ErrorFor(HttpStatusCode.Forbidden, "5301",
            "Request blocked by Auth: principal [x] does not have required RBAC permissions to perform action [items/delete]\nActivityId: 1");
        denied.Code.Should().Be("permission_denied");
        denied.Message.Should().Contain("substatus 5301").And.Contain("items/delete").And.NotContain("ActivityId");

        ArtifactStore.ErrorFor(HttpStatusCode.Unauthorized, null, null).Code.Should().Be("unauthenticated");
        ArtifactStore.ErrorFor(HttpStatusCode.ServiceUnavailable, null, null).Code.Should().Be("unavailable");
    }
}

/// <summary>The tools with passthrough on: without a Cosmos DB token, a call fails before Cosmos DB is reached.</summary>
[Collection("Environment variables")]
public class CosmosTokenPassthroughMcpTests : IClassFixture<McpTestApplicationFactory>
{
    private readonly HttpClient _client;

    public CosmosTokenPassthroughMcpTests(McpTestApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    private async Task<JsonNode> Call(string name, object arguments)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method = "tools/call", @params = new { name, arguments } }),
                Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        var text = await (await _client.SendAsync(request)).Content.ReadAsStringAsync();
        var json = text.TrimStart().StartsWith('{') ? text : text.Split('\n').First(l => l.StartsWith("data:"))["data:".Length..];
        return JsonNode.Parse(json)!["result"]!;
    }

    [Theory]
    [InlineData("db_get")]
    [InlineData("db_set")]
    [InlineData("db_delete")]
    public async Task Calls_without_a_token_are_unauthenticated(string tool)
    {
        Environment.SetEnvironmentVariable("COSMOS_TOKEN_PASSTHROUGH", "true");
        try
        {
            var result = await Call(tool, new { path = "ideas/i1", data = new { text = "hi" } });
            result["isError"]!.GetValue<bool>().Should().BeTrue();
            result["content"]![0]!["text"]!.GetValue<string>().Should().StartWith("unauthenticated: ");
        }
        finally
        {
            Environment.SetEnvironmentVariable("COSMOS_TOKEN_PASSTHROUGH", null);
        }
    }
}
