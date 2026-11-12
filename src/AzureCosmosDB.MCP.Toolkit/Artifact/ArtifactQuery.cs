// Filters, ordering and limits over one collection, evaluated in memory against top-level fields (the contract
// says the store scans the collection, without indexes), and the merge that db_update applies.
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactFilter(string Field, string Op, JsonNode? Value);

public sealed record ArtifactOrder(string Field, string Dir);

public sealed record ArtifactQueryOptions(IReadOnlyList<ArtifactFilter> Where, ArtifactOrder? OrderBy, int? Limit);

public static class ArtifactQuery
{
    public const int MaxScan = 5000;

    private static readonly HashSet<string> Ops = ["==", "!=", "<", "<=", ">", ">=", "in", "not-in", "array-contains"];

    public static ArtifactQueryOptions Check(JsonNode? where, JsonNode? orderBy, int? limit)
    {
        var filters = new List<ArtifactFilter>();
        if (where is not null)
        {
            if (where is not JsonArray list || list.Count > 10) throw ArtifactDbException.Invalid("at most 10 filters");
            foreach (var w in list)
            {
                if (w is not JsonObject f || !TryString(f["field"], out var field) || !TryString(f["op"], out var op) || !Ops.Contains(op))
                    throw ArtifactDbException.Invalid($"bad filter {w?.ToJsonString()}");
                var value = f["value"]?.DeepClone();
                if (op is "in" or "not-in" && (value is not JsonArray arr || arr.Count > 30))
                    throw ArtifactDbException.Invalid($"\"{op}\" needs an array of at most 30 values");
                filters.Add(new ArtifactFilter(field, op, value));
            }
        }

        ArtifactOrder? order = null;
        if (orderBy is not null)
        {
            if (orderBy is not JsonObject o || !TryString(o["field"], out var field)) throw ArtifactDbException.Invalid("bad orderBy");
            var dir = o["dir"] is null ? "asc" : TryString(o["dir"], out var d) ? d : "";
            if (dir is not ("asc" or "desc")) throw ArtifactDbException.Invalid("bad orderBy");
            order = new ArtifactOrder(field, dir);
        }

        if (limit is < 1 or > 1000) throw ArtifactDbException.Invalid("limit must be an integer from 1 to 1000");
        return new ArtifactQueryOptions(filters, order, limit);
    }

    public static List<ArtifactRecord> Run(IEnumerable<ArtifactRecord> docs, ArtifactQueryOptions q)
    {
        var output = docs.Where(d => q.Where.All(w => Matches(d.Data, w))).ToList();
        if (q.OrderBy is { } order)
        {
            var sign = order.Dir == "desc" ? -1 : 1;
            output.Sort((a, b) =>
            {
                var ha = a.Data.ContainsKey(order.Field);
                var hb = b.Data.ContainsKey(order.Field);
                if (ha != hb) return ha ? -1 : 1; // missing field sorts last, either direction
                var c = Compare(a.Data[order.Field], b.Data[order.Field]) * sign;
                return c != 0 ? c : string.CompareOrdinal(a.Id, b.Id);
            });
        }
        else
        {
            output.Sort((a, b) => string.CompareOrdinal(a.Id, b.Id));
        }
        return q.Limit is { } n ? output.Take(n).ToList() : output;
    }

    /// <summary>For db_update: nested objects merge; anything else, arrays included, replaces.</summary>
    public static JsonObject DeepMerge(JsonObject target, JsonObject patch)
    {
        var output = target.DeepClone().AsObject();
        foreach (var (key, value) in patch)
        {
            if (value is JsonObject pv && output[key] is JsonObject tv) output[key] = DeepMerge(tv, pv);
            else output[key] = value?.DeepClone();
        }
        return output;
    }

    private static bool TryString(JsonNode? node, out string value)
    {
        value = "";
        return node is JsonValue v && v.TryGetValue(out value!);
    }

    // Cross-type order: null < booleans < numbers < strings < arrays < objects (as Firestore does).
    private static int TypeRank(JsonNode? v) => v?.GetValueKind() switch
    {
        null or JsonValueKind.Null or JsonValueKind.Undefined => 0,
        JsonValueKind.True or JsonValueKind.False => 1,
        JsonValueKind.Number => 2,
        JsonValueKind.String => 3,
        JsonValueKind.Array => 4,
        _ => 5,
    };

    public static int Compare(JsonNode? a, JsonNode? b)
    {
        int ta = TypeRank(a), tb = TypeRank(b);
        if (ta != tb) return ta - tb;
        return ta switch
        {
            0 => 0,
            1 => a!.GetValue<bool>().CompareTo(b!.GetValue<bool>()),
            2 => a!.GetValue<double>().CompareTo(b!.GetValue<double>()),
            3 => Math.Sign(string.CompareOrdinal(a!.GetValue<string>(), b!.GetValue<string>())),
            _ => Math.Sign(string.CompareOrdinal(a!.ToJsonString(), b!.ToJsonString())),
        };
    }

    private static bool Same(JsonNode? a, JsonNode? b) => JsonNode.DeepEquals(a, b);

    private static bool Matches(JsonObject data, ArtifactFilter f)
    {
        var has = data.TryGetPropertyValue(f.Field, out var v);
        bool Ordered(Func<int, bool> test) => has && TypeRank(v) == TypeRank(f.Value) && test(Compare(v, f.Value));
        return f.Op switch
        {
            "==" => has && Same(v, f.Value),
            "!=" => has && !Same(v, f.Value),
            "<" => Ordered(c => c < 0),
            "<=" => Ordered(c => c <= 0),
            ">" => Ordered(c => c > 0),
            ">=" => Ordered(c => c >= 0),
            "in" => has && f.Value!.AsArray().Any(x => Same(v, x)),
            "not-in" => has && !f.Value!.AsArray().Any(x => Same(v, x)),
            "array-contains" => v is JsonArray arr && arr.Any(x => Same(x, f.Value)),
            _ => false,
        };
    }
}
