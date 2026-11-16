// Tickets: how the artifact's page proves who is signed in. The page is a Free-plan Static Web App that signs people
// in with its preconfigured Microsoft Entra provider (no app registration of ours). That sign-in gives the page no
// token, so the Static Web App's "ticket" managed function (src/runtime/api/ticket) reads who is signed in from the
// x-ms-client-principal header it receives and signs a short-lived ticket with TICKET_SECRET, which this server holds
// too. See docs/swa-free-ticket-auth.md.
//
//   ticket  = base64url(payload) "." base64url(HMAC-SHA256(secret, base64url(payload)))
//   payload = {"sub": "<sign-in email>", "aud": "<this server's host name>", "iat": <unix s>, "exp": <unix s>}
//
// The page sends it as "Authorization: Bearer <ticket>". A ticket is accepted when its signature matches
// TICKET_SECRET (or TICKET_SECRET_PREVIOUS, while changing secrets), it hasn't expired, it lives at most
// MaxLifetime, and its aud is TICKET_AUDIENCE. Without TICKET_SECRET no ticket is accepted.
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed class TicketAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Ticket";
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>Whether the request carries a bearer token shaped like a ticket (two parts; a JWT has three).</summary>
    public static bool HasTicket(HttpRequest request) => Bearer(request) is { } token && token.Split('.').Length == 2;

    private static string? Bearer(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : null;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!HasTicket(Request)) return Task.FromResult(AuthenticateResult.NoResult());
        var principal = Validate(Bearer(Request)!, DateTimeOffset.UtcNow);
        if (principal is null)
        {
            Logger.LogInformation("Refused a ticket: bad signature, expired, or for another server");
            return Task.FromResult(AuthenticateResult.Fail("invalid ticket"));
        }
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    /// <summary>The person a ticket names, or null unless it's genuine, current and for this server.</summary>
    public static ClaimsPrincipal? Validate(string ticket, DateTimeOffset now)
    {
        var parts = ticket.Split('.');
        if (parts.Length != 2) return null;
        var secrets = new[] { "TICKET_SECRET", "TICKET_SECRET_PREVIOUS" }
            .Select(Environment.GetEnvironmentVariable)
            .Where(s => !string.IsNullOrEmpty(s))
            .ToList();
        if (secrets.Count == 0) return null;

        try
        {
            var signature = WebEncoders.Base64UrlDecode(parts[1]);
            var signed = Encoding.ASCII.GetBytes(parts[0]);
            if (!secrets.Any(s => CryptographicOperations.FixedTimeEquals(
                    HMACSHA256.HashData(Encoding.UTF8.GetBytes(s!), signed), signature)))
                return null;

            using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[0]));
            var root = payload.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            string? Text(string name) =>
                root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            long? Seconds(string name) =>
                root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;

            var email = Text("sub")?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(email) || !email.Contains('@')) return null;
            var audience = Environment.GetEnvironmentVariable("TICKET_AUDIENCE");
            if (!string.IsNullOrEmpty(audience) && !string.Equals(Text("aud"), audience, StringComparison.OrdinalIgnoreCase))
                return null;
            if (Seconds("iat") is not { } iat || Seconds("exp") is not { } exp) return null;
            var issued = DateTimeOffset.FromUnixTimeSeconds(iat);
            var expires = DateTimeOffset.FromUnixTimeSeconds(exp);
            if (expires <= now - ClockSkew || issued > now + ClockSkew || expires - issued > MaxLifetime) return null;

            return new ClaimsPrincipal(new ClaimsIdentity([new Claim("email", email)], SchemeName));
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
        {
            return null;
        }
    }
}
