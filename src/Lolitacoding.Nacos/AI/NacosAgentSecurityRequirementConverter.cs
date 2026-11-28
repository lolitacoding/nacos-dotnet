using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lolitacoding.Nacos.AI;

/// <summary>
/// Reads and writes a card's A2A 1.0 security requirements, accepting the older flat shape on read.
/// </summary>
/// <remarks>
/// <para>
/// A2A 1.0 defines a requirement as <c>{"schemes":{"oauth2":{"list":["read"]}}}</c>, where the
/// <c>list</c> member is optional and an omitted one means an empty scope list. Nacos stored the
/// older, flatter <c>{"oauth2":["read"]}</c> shape under the same member before it adopted the
/// standard model, so a card published by a client built against that model is still in the
/// registry.
/// </para>
/// <para>
/// Reads therefore accept either shape, deciding per requirement object: a <c>schemes</c> object
/// selects the standard form, anything else is parsed as the flat form and fails if it is not
/// scheme-to-string-array. Writes always use the standard form, which is what a server from the
/// 3.3.1 line on expects; a 3.3.0 server only understands the flat form, so a card that carries
/// security requirements has to be published to a newer one.
/// </para>
/// </remarks>
internal sealed class NacosAgentCardSecurityRequirementsConverter
    : JsonConverter<List<NacosAgentSecurityRequirement>>
{
    /// <inheritdoc />
    public override List<NacosAgentSecurityRequirement> Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        NacosAgentSecurityRequirementJson.ReadArray(ref reader, allowLegacy: true);

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer,
        List<NacosAgentSecurityRequirement> value,
        JsonSerializerOptions options) =>
        NacosAgentSecurityRequirementJson.WriteArray(writer, value);
}

/// <summary>
/// Reads and writes a skill's A2A 1.0 security requirements, in the standard shape only.
/// </summary>
/// <remarks>
/// The skill-level member is additive and never had a flat form, so a flat requirement is refused
/// rather than decoded into one that lost its scopes. Accepting it would silently widen or narrow
/// access, which is worse than failing.
/// </remarks>
internal sealed class NacosAgentSkillSecurityRequirementsConverter
    : JsonConverter<List<NacosAgentSecurityRequirement>>
{
    /// <inheritdoc />
    public override List<NacosAgentSecurityRequirement> Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        NacosAgentSecurityRequirementJson.ReadArray(ref reader, allowLegacy: false);

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer,
        List<NacosAgentSecurityRequirement> value,
        JsonSerializerOptions options) =>
        NacosAgentSecurityRequirementJson.WriteArray(writer, value);
}

/// <summary>
/// The reading and writing both security-requirement converters share.
/// </summary>
internal static class NacosAgentSecurityRequirementJson
{
    /// <summary>
    /// Reads a requirements array.
    /// </summary>
    /// <param name="reader">The reader, positioned on the array.</param>
    /// <param name="allowLegacy">Whether the flat requirement shape is accepted.</param>
    /// <returns>The requirements.</returns>
    public static List<NacosAgentSecurityRequirement> ReadArray(
        ref Utf8JsonReader reader,
        bool allowLegacy)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Security requirements must be a JSON array.");
        }

        var requirements = new List<NacosAgentSecurityRequirement>();

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                return requirements;
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);

            requirements.Add(ReadRequirement(document.RootElement, allowLegacy));
        }

        throw new JsonException("The security requirements array was not closed.");
    }

    /// <summary>
    /// Writes a requirements array in the standard shape.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <param name="requirements">The requirements.</param>
    public static void WriteArray(
        Utf8JsonWriter writer,
        IReadOnlyList<NacosAgentSecurityRequirement> requirements)
    {
        writer.WriteStartArray();

        foreach (NacosAgentSecurityRequirement requirement in requirements)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("schemes");
            writer.WriteStartObject();

            if (requirement?.Schemes is not null)
            {
                foreach (KeyValuePair<string, NacosAgentSecurityScope> scheme in requirement.Schemes)
                {
                    writer.WritePropertyName(scheme.Key);
                    writer.WriteStartObject();

                    if (scheme.Value?.List is not null)
                    {
                        writer.WritePropertyName("list");
                        writer.WriteStartArray();

                        foreach (string scope in scheme.Value.List)
                        {
                            writer.WriteStringValue(scope);
                        }

                        writer.WriteEndArray();
                    }

                    writer.WriteEndObject();
                }
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static NacosAgentSecurityRequirement ReadRequirement(
        JsonElement root,
        bool allowLegacy)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("A security requirement must be a JSON object.");
        }

        if (TryGetSchemes(root, out JsonElement schemes))
        {
            return ReadStandard(schemes);
        }

        if (!allowLegacy)
        {
            throw new JsonException(
                "A skill's security requirement must have a schemes object.");
        }

        return ReadLegacy(root);
    }

    private static bool TryGetSchemes(JsonElement root, out JsonElement schemes)
    {
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (string.Equals(property.Name, "schemes", StringComparison.OrdinalIgnoreCase) &&
                property.Value.ValueKind == JsonValueKind.Object)
            {
                // Only an object is the standard member. A flat requirement could name a scheme
                // called "schemes", so anything else falls through to the legacy reader, which
                // then validates it as a scheme-to-array map.
                schemes = property.Value;
                return true;
            }
        }

        schemes = default;
        return false;
    }

    private static NacosAgentSecurityRequirement ReadStandard(JsonElement schemes)
    {
        var requirement = new NacosAgentSecurityRequirement
        {
            Schemes = new Dictionary<string, NacosAgentSecurityScope>(StringComparer.Ordinal),
        };

        foreach (JsonProperty scheme in schemes.EnumerateObject())
        {
            var scope = new NacosAgentSecurityScope();

            switch (scheme.Value.ValueKind)
            {
                case JsonValueKind.Object:
                    if (TryGetProperty(scheme.Value, "list", out JsonElement list))
                    {
                        scope.List = ReadStringArray(list, scheme.Name);
                    }

                    break;

                case JsonValueKind.Null:
                    break;

                default:
                    throw new JsonException(
                        $"Security scheme '{scheme.Name}' must be an object with an optional list.");
            }

            requirement.Schemes[scheme.Name] = scope;
        }

        return requirement;
    }

    private static NacosAgentSecurityRequirement ReadLegacy(JsonElement root)
    {
        var requirement = new NacosAgentSecurityRequirement
        {
            Schemes = new Dictionary<string, NacosAgentSecurityScope>(StringComparer.Ordinal),
        };

        foreach (JsonProperty scheme in root.EnumerateObject())
        {
            requirement.Schemes[scheme.Name] = new NacosAgentSecurityScope
            {
                List = ReadStringArray(scheme.Value, scheme.Name),
            };
        }

        return requirement;
    }

    private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static List<string> ReadStringArray(JsonElement element, string scheme)
    {
        if (element.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException($"Security scheme '{scheme}' must map to an array of scopes.");
        }

        var scopes = new List<string>();

        foreach (JsonElement scope in element.EnumerateArray())
        {
            if (scope.ValueKind != JsonValueKind.String)
            {
                throw new JsonException($"Security scheme '{scheme}' has a scope that is not a string.");
            }

            scopes.Add(scope.GetString()!);
        }

        return scopes;
    }
}
