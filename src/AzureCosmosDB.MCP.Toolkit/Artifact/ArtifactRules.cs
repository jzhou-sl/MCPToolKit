// Access rules for the artifact's database, compatible with the Claude artifact `db` contract.
//
// A caller holds one level: view < interact < admin < owner (from their app role, see ArtifactViewer). The artifact
// declares rules ({path, read?, write?}) in capabilities.json giving the minimum level for each action at a path
// and below. The root defaults to read: "view", write: "interact". A deeper rule overrides a shallower one; an unset
// level inherits. "self" is a level nobody holds. A rule path ending in "/{self}" names each caller's own subtree
// under that prefix: others' subtrees are private unless a rule at the prefix opens them, and on the caller's own
// subtree whichever of the prefix rule and the {self} rule gives more applies. "data/users/{self}" is implicit.
using System.Text.Json.Nodes;

namespace AzureCosmosDB.MCP.Toolkit.Artifact;

public sealed record ArtifactRule(string Path, string? Read, string? Write);

public static class ArtifactRules
{
    private const string Self = "{self}";
    private const int MaxRules = 64;

    private static readonly Dictionary<string, double> Rank = new()
    {
        ["view"] = 1, ["interact"] = 2, ["admin"] = 3, ["owner"] = 4, ["self"] = double.PositiveInfinity,
    };

    private static string Looser(string a, string b) => Rank[a] <= Rank[b] ? a : b;

    /// <summary>Validates the rules from capabilities.json (db.rules); throws describing the first problem.</summary>
    public static IReadOnlyList<ArtifactRule> Validate(JsonNode? rules)
    {
        if (rules is null) return [];
        if (rules is not JsonArray list) throw ArtifactDbException.Invalid("db.rules must be an array");
        if (list.Count > MaxRules) throw ArtifactDbException.Invalid($"db.rules has more than {MaxRules} rules");

        var seen = new HashSet<string>();
        var output = new List<ArtifactRule>();
        foreach (var node in list)
        {
            if (node is not JsonObject r || r["path"] is not JsonValue pv || !pv.TryGetValue<string>(out var raw))
                throw ArtifactDbException.Invalid("each rule needs a string path");
            var path = raw.Trim('/');
            if (!seen.Add(path)) throw ArtifactDbException.Invalid($"two rules for path \"{path}\"");
            if (path.Length > 0)
            {
                var segs = path.Split('/');
                for (var i = 0; i < segs.Length; i++)
                {
                    if (segs[i] != Self) continue;
                    if (i != segs.Length - 1) throw ArtifactDbException.Invalid($"{{self}} must be the last segment (\"{path}\")");
                    if (i == 0) throw ArtifactDbException.Invalid($"{{self}} needs a prefix (\"{path}\")");
                }
                var literal = string.Join('/', segs.Where(s => s != Self));
                if (literal.Length > 0) ArtifactPaths.Split(literal);
            }
            string? Level(string key)
            {
                var v = r[key];
                if (v is null) return null;
                if (v is not JsonValue jv || !jv.TryGetValue<string>(out var s) || !Rank.ContainsKey(s))
                    throw ArtifactDbException.Invalid($"rule \"{path}\": {key} must be one of view, interact, admin, owner, self");
                return s;
            }
            output.Add(new ArtifactRule(path, Level("read"), Level("write")));
        }

        var byPath = output.ToDictionary(r => r.Path);
        foreach (var r in output)
        {
            if (r.Read is not null && r.Write is not null && Rank[r.Write] < Rank[r.Read])
                throw ArtifactDbException.Invalid($"rule \"{r.Path}\": write is below read (writing implies reading)");
            if (r.Read == "self" && r.Write != "self")
                throw ArtifactDbException.Invalid($"rule \"{r.Path}\": read \"self\" needs write \"self\"");
            var isSelfPrefix = byPath.ContainsKey(r.Path.Length == 0 ? Self : $"{r.Path}/{Self}");
            if ((r.Read == "self" || r.Write == "self") && !isSelfPrefix)
                throw ArtifactDbException.Invalid($"rule \"{r.Path}\": \"self\" is allowed only on the prefix of a {{self}} rule");
            if (isSelfPrefix && (r.Read is null || r.Write is null))
                throw ArtifactDbException.Invalid($"rule \"{r.Path}\" is the prefix of a {{self}} rule, so it must set both read and write");
            if (r.Path.EndsWith(Self))
            {
                if (r.Read == "self" || r.Write == "self")
                    throw ArtifactDbException.Invalid($"rule \"{r.Path}\": \"self\" goes on the prefix rule, not the {{self}} rule");
                var prefix = r.Path[..^(Self.Length + 1)];
                if (byPath.TryGetValue(prefix, out var p) && (p.Read == "self" || p.Write == "self") && (r.Read is null || r.Write is null))
                    throw ArtifactDbException.Invalid($"rule \"{r.Path}\": beside a prefix that uses \"self\", set both read and write");
            }
        }
        return output;
    }

    /// <summary>
    /// The minimum level needed for <paramref name="action"/> ("read" or "write") on the document at
    /// <paramref name="path"/>, for the caller whose id is <paramref name="viewerId"/>. "self" means nobody may.
    /// </summary>
    public static string RequiredLevel(IReadOnlyList<ArtifactRule> rules, string path, string action, string? viewerId)
    {
        var byPath = rules.ToDictionary(r => r.Path);
        byPath.TryAdd($"data/users/{Self}", new ArtifactRule($"data/users/{Self}", null, null));

        var segs = path.Split('/');
        string read = "view", write = "interact";
        void Apply(string key)
        {
            if (!byPath.TryGetValue(key, out var r)) return;
            read = r.Read ?? read;
            write = r.Write ?? write;
        }

        Apply("");
        for (var i = 1; i <= segs.Length; i++)
        {
            var parent = string.Join('/', segs[..(i - 1)]);
            if (parent.Length > 0 && byPath.TryGetValue($"{parent}/{Self}", out var selfRule))
            {
                var explicitPrefix = byPath.ContainsKey(parent);
                if (viewerId is not null && segs[i - 1] == viewerId)
                {
                    var ownRead = selfRule.Read ?? read;
                    var ownWrite = selfRule.Write ?? write;
                    if (explicitPrefix) { read = Looser(read, ownRead); write = Looser(write, ownWrite); }
                    else { read = ownRead; write = ownWrite; }
                }
                else if (!explicitPrefix)
                {
                    read = "self";
                    write = "self";
                }
            }
            Apply(string.Join('/', segs[..i]));
        }
        return action == "read" ? read : write;
    }

    /// <summary>Whether a caller at <paramref name="level"/> meets <paramref name="required"/>. Nobody meets "self".</summary>
    public static bool Meets(string? level, string required) =>
        level is not null && required != "self" && Rank[level] >= Rank[required];

    public static bool CanAccess(IReadOnlyList<ArtifactRule> rules, string path, string action, ArtifactViewer viewer) =>
        Meets(viewer.Level, RequiredLevel(rules, path, action, viewer.Id));
}
