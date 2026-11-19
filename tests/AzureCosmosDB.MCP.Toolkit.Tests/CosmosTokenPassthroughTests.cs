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

    // What az account get-access-token --resource <account endpoint> gives (its aud is Cosmos DB's application ID),
    // unsigned: Cosmos DB checks signatures, the server doesn't.
    private static string Token(
        string upn = "jane.doe@example.com", string tid = Tenant, string aud = "a232010e-820c-4083-83bb-3ace5fc29d0b", int expiresIn = 3600)
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
        // The URL forms are Cosmos DB audiences too: https://cosmos.azure.com, and the account's own endpoint with or
        // without the port and slash.
        CosmosTokenPassthrough.Check(Token(aud: "https://cosmos.azure.com/"), "jane.doe@example.com", Now).Should().NotBeNull();
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

    private static bool IsCosmosBearer(string? authorization)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        if (authorization is not null) context.Request.Headers.Authorization = authorization;
        return CosmosTokenPassthrough.IsCosmosBearer(context.Request);
    }

    // Claude Code sends the Cosmos DB token as its bearer token; such requests go to the CosmosToken scheme.
    [Fact]
    public void A_cosmos_db_bearer_token_is_recognised() =>
        WithSettings(new() { ["COSMOS_ENDPOINT"] = Endpoint }, () =>
        {
            IsCosmosBearer("Bearer " + Token()).Should().BeTrue();
            IsCosmosBearer("Bearer " + Token(aud: "https://cosmos-alz-test.documents.azure.com:443/")).Should().BeTrue();
            IsCosmosBearer("Bearer " + Token(aud: "api://mcp-server")).Should().BeFalse();
            IsCosmosBearer("Bearer eyJzdWIiOiJ4In0.c2ln").Should().BeFalse(); // a ticket: two parts
            IsCosmosBearer("Bearer not.a.jwt").Should().BeFalse();
            IsCosmosBearer(null).Should().BeFalse();
        });

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

/// <summary>On-behalf-of: an Entra caller reaches Cosmos DB with a token got for them; everyone else still pastes one.</summary>
[Collection("Environment variables")]
public class CosmosOnBehalfOfTests
{
    private sealed class FakeCredential : Azure.Core.TokenCredential
    {
        private static readonly Azure.Core.AccessToken Token = new("cosmos-token", DateTimeOffset.UtcNow.AddHours(1));
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext r, CancellationToken c) => Token;
        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext r, CancellationToken c) => ValueTask.FromResult(Token);
    }

    private static readonly ArtifactViewer Jane = new("jane.doe@example.com", null, "jane.doe@example.com");

    // A request as the Entra scheme (or another) leaves it: an authenticated identity and the bearer it came with.
    private static Microsoft.AspNetCore.Http.HttpContext Caller(string authenticationType, string bearer, string? cosmosHeader = null)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds().ToString())],
            authenticationType));
        context.Request.Headers.Authorization = "Bearer " + bearer;
        if (cosmosHeader is not null) context.Request.Headers[CosmosTokenPassthrough.Header] = cosmosHeader;
        return context;
    }

    private static void WithOnBehalfOf(Action<List<string>> test, string? clientId = "22222222-2222-2222-2222-222222222222")
    {
        var settings = new Dictionary<string, string?>
        {
            ["AzureAd__TenantId"] = "11111111-1111-1111-1111-111111111111",
            ["AzureAd__ClientId"] = clientId,
            ["COSMOS_ENDPOINT"] = "https://cosmos-alz-test.documents.azure.com:443/",
        };
        var exchanged = new List<string>();
        var original = CosmosOnBehalfOf.CredentialFor;
        CosmosOnBehalfOf.CredentialFor = bearer => { exchanged.Add(bearer); return new FakeCredential(); };
        foreach (var (k, v) in settings) Environment.SetEnvironmentVariable(k, v);
        try { test(exchanged); }
        finally
        {
            CosmosOnBehalfOf.CredentialFor = original;
            foreach (var k in settings.Keys) Environment.SetEnvironmentVariable(k, null);
        }
    }

    [Fact]
    public void An_entra_caller_is_exchanged_and_needs_no_pasted_token() => WithOnBehalfOf(exchanged =>
    {
        var bearer = "entra." + Guid.NewGuid().ToString("N") + ".sig";
        ArtifactStore.For(Caller("Bearer", bearer, cosmosHeader: "ignored"), Jane).Should().NotBeSameAs(ArtifactStore.Shared);
        exchanged.Should().Equal(bearer);
    });

    [Fact]
    public void Ticket_callers_still_need_a_pasted_token() => WithOnBehalfOf(exchanged =>
    {
        var act = () => ArtifactStore.For(Caller(TicketAuthenticationHandler.SchemeName, "a.ticket"), Jane);
        act.Should().Throw<ArtifactDbException>().Which.Code.Should().Be("unauthenticated");
        exchanged.Should().BeEmpty();
    });

    [Fact]
    public void Without_the_app_registration_entra_callers_need_a_pasted_token_too() => WithOnBehalfOf(exchanged =>
    {
        var act = () => ArtifactStore.For(Caller("Bearer", "entra.token.sig"), Jane);
        act.Should().Throw<ArtifactDbException>().Which.Code.Should().Be("unauthenticated");
        exchanged.Should().BeEmpty();
    }, clientId: null);

    [Fact]
    public void Failed_exchanges_become_tool_errors()
    {
        CosmosOnBehalfOf.Failure(new Azure.Identity.AuthenticationFailedException("AADSTS65001: The user or administrator has not consented"))!
            .Code.Should().Be("unauthenticated");
        CosmosOnBehalfOf.Failure(new InvalidOperationException("wrapped",
            new Azure.Identity.AuthenticationFailedException("AADSTS700213: No matching federated identity record found")))!
            .Code.Should().Be("unavailable");
        CosmosOnBehalfOf.Failure(new InvalidOperationException("something else")).Should().BeNull();
    }
}
