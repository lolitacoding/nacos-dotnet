using System.Text.Json;
using Lolitacoding.Nacos.AI;
using Lolitacoding.Nacos.Protocol;

namespace Lolitacoding.Nacos.Tests.AI;

/// <summary>
/// Verifies the JSON contract of an agent card's security requirements.
/// </summary>
/// <remarks>
/// A2A 1.0 nests each scheme's scopes under a <c>list</c> member, while cards stored by Nacos before
/// the standard model used the flat 0.3 shape. Both have to be readable, and only the standard shape
/// may be written, because that is what a server from the 3.3.1 line on expects.
/// </remarks>
public sealed class NacosAgentCardModelTests
{
    [Fact]
    public void Deserialize_ReadsTheStandardSecurityRequirementsShape()
    {
        const string Json = """
            {
              "name": "planner",
              "version": "1.0.0",
              "securityRequirements": [
                { "schemes": { "oauth2": { "list": ["read", "write"] }, "apiKey": {} } }
              ],
              "skills": [
                {
                  "id": "plan",
                  "securityRequirements": [
                    { "schemes": { "oauth2": { "list": ["plan"] } } }
                  ]
                }
              ]
            }
            """;

        NacosAgentCardDetail card = Deserialize(Json);

        NacosAgentSecurityRequirement requirement =
            card.SecurityRequirements.ShouldNotBeNull().ShouldHaveSingleItem();

        requirement.Schemes.ShouldNotBeNull()["oauth2"].List
            .ShouldBe(new[] { "read", "write" });

        // An omitted list is an empty scope list, not a scheme that was lost.
        requirement.Schemes["apiKey"].List.ShouldBeNull();

        NacosAgentSkill skill = card.Skills.ShouldNotBeNull().ShouldHaveSingleItem();

        skill.SecurityRequirements.ShouldNotBeNull()
            .ShouldHaveSingleItem()
            .Schemes.ShouldNotBeNull()["oauth2"].List
            .ShouldBe(new[] { "plan" });
    }

    [Fact]
    public void Deserialize_ReadsTheLegacyFlatSecurityRequirementsShape()
    {
        const string Json = """
            {
              "name": "planner",
              "securityRequirements": [
                { "oauth2": ["read"] },
                { "apiKey": [] }
              ]
            }
            """;

        NacosAgentCardDetail card = Deserialize(Json);

        List<NacosAgentSecurityRequirement> requirements =
            card.SecurityRequirements.ShouldNotBeNull();

        requirements.Count.ShouldBe(2);
        requirements[0].Schemes.ShouldNotBeNull()["oauth2"].List.ShouldBe(new[] { "read" });
        requirements[1].Schemes.ShouldNotBeNull()["apiKey"].List.ShouldBeEmpty();
    }

    [Fact]
    public void Deserialize_RejectsTheLegacyFlatShapeForASkill()
    {
        const string Json = """
            {
              "skills": [
                { "id": "plan", "securityRequirements": [ { "oauth2": ["read"] } ] }
              ]
            }
            """;

        // The skill-level member never had a flat form, so accepting one would invent scopes.
        Should.Throw<JsonException>(() => Deserialize(Json));
    }

    [Fact]
    public void Serialize_WritesTheStandardShape()
    {
        var card = new NacosAgentCardDetail
        {
            Name = "planner",
            Version = "1.0.0",
            SecurityRequirements =
            [
                new NacosAgentSecurityRequirement
                {
                    Schemes = new Dictionary<string, NacosAgentSecurityScope>
                    {
                        ["oauth2"] = new() { List = ["read"] },
                        ["apiKey"] = new(),
                    },
                },
            ],
        };

        string json = JsonSerializer.Serialize(
            card, NacosJsonContext.Default.NacosAgentCardDetail);

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement requirement = document.RootElement.GetProperty("securityRequirements")[0];

        // The flat member is not written; the schemes object is the standard shape.
        requirement.TryGetProperty("oauth2", out _).ShouldBeFalse();

        JsonElement schemes = requirement.GetProperty("schemes");
        schemes.GetProperty("oauth2").GetProperty("list")[0].GetString().ShouldBe("read");

        // A scheme with no scopes omits the list rather than writing an empty one.
        schemes.GetProperty("apiKey").TryGetProperty("list", out _).ShouldBeFalse();
    }

    [Fact]
    public void Deserialize_KeepsAnEmptyRequirementsListDistinctFromAnAbsentOne()
    {
        NacosAgentCardDetail empty = Deserialize("""{ "securityRequirements": [] }""");
        empty.SecurityRequirements.ShouldNotBeNull().ShouldBeEmpty();

        NacosAgentCardDetail absent = Deserialize("""{ "name": "planner" }""");
        absent.SecurityRequirements.ShouldBeNull();
    }

    [Theory]
    [InlineData("""{ "securityRequirements": [ { "oauth2": "read" } ] }""")]
    [InlineData("""{ "securityRequirements": [ { "schemes": "oauth2" } ] }""")]
    [InlineData("""{ "securityRequirements": [ { "schemes": { "oauth2": { "list": "read" } } } ] }""")]
    [InlineData("""{ "securityRequirements": [ { "schemes": { "oauth2": { "list": [1] } } } ] }""")]
    [InlineData("""{ "securityRequirements": [ null ] }""")]
    public void Deserialize_RejectsMalformedSecurityRequirements(string json)
    {
        // Losing a scope would silently widen or narrow access, so malformed data must fail rather
        // than decode to an empty requirement.
        Should.Throw<JsonException>(() => Deserialize(json));
    }

    private static NacosAgentCardDetail Deserialize(string json) =>
        JsonSerializer.Deserialize(json, NacosJsonContext.Default.NacosAgentCardDetail)
            .ShouldNotBeNull();
}
