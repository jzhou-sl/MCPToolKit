// Document paths and bodies for the artifact database, matching the Claude artifact `db` contract: even segment
// counts are documents, odd are collections; segments use letters, digits and `_ - . ~ : @ +` (never `.` or `..`
// alone); at most 200 bytes a segment, 1000 bytes and 16 segments a path. Bodies are JSON objects, at most 256 KiB
// and 32 levels deep.
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

/// <summary>An error with one of the contract's stable codes (invalid_argument, resource_exhausted, unavailable).</summary>
public sealed class ArtifactDbException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;

    public static ArtifactDbException Invalid(string message) => new("invalid_argument", message);
}

public static partial class ArtifactPaths
{
    [GeneratedRegex(@"^[A-Za-z0-9_\-.~:@+]+$")]
    private static partial Regex Segment();

    public static string[] Split(string? path)
    {
        if (string.IsNullOrEmpty(path)) throw ArtifactDbException.Invalid("path must be a non-empty string");
        if (Encoding.UTF8.GetByteCount(path) > 1000) throw ArtifactDbException.Invalid("path is longer than 1000 bytes");
        var segs = path.Split('/');
        if (segs.Length > 16) throw ArtifactDbException.Invalid("path has more than 16 segments");
        foreach (var s in segs)
        {
            if (s.Length == 0) throw ArtifactDbException.Invalid("path has an empty segment");
            if (s is "." or "..") throw ArtifactDbException.Invalid("path segment cannot be . or ..");
            if (!Segment().IsMatch(s)) throw ArtifactDbException.Invalid($"path segment \"{s}\" has characters outside letters, digits and _ - . ~ : @ +");
            if (Encoding.UTF8.GetByteCount(s) > 200) throw ArtifactDbException.Invalid("path segment is longer than 200 bytes");
        }
        return segs;
    }

    public static string Document(string? path)
    {
        var segs = Split(path);
        if (segs.Length % 2 != 0) throw ArtifactDbException.Invalid($"a document path needs an even number of segments (got {segs.Length})");
        return path!;
    }

    public static string Collection(string? path)
    {
        var segs = Split(path);
        if (segs.Length % 2 != 1) throw ArtifactDbException.Invalid($"a collection path needs an odd number of segments (got {segs.Length})");
        return path!;
    }

    /// <summary>The collection a document belongs to: everything but the last segment.</summary>
    public static string Parent(string path) => path[..path.LastIndexOf('/')];

    /// <summary>The document's id: its last segment.</summary>
    public static string Id(string path) => path[(path.LastIndexOf('/') + 1)..];

    public static JsonObject CheckBody(JsonNode? data)
    {
        if (data is not JsonObject obj) throw ArtifactDbException.Invalid("a document body must be a JSON object");
        var json = obj.ToJsonString();
        if (Encoding.UTF8.GetByteCount(json) > 256 * 1024) throw ArtifactDbException.Invalid("a document body is larger than 256 KiB");
        if (Depth(obj) > 32) throw ArtifactDbException.Invalid("a document body is nested more than 32 levels deep");
        return JsonNode.Parse(json)!.AsObject();
    }

    private static int Depth(JsonNode? node) => node switch
    {
        JsonObject o => 1 + o.Select(p => Depth(p.Value)).DefaultIfEmpty(0).Max(),
        JsonArray a => 1 + a.Select(Depth).DefaultIfEmpty(0).Max(),
        _ => 0,
    };
}
