using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class CrowdsourcedYaraResult
    {
        [JsonProperty("description")]
        public string Description { get; set; }
        [JsonProperty("source")]
        public string Source { get; set; }
        [JsonProperty("author")]
        public string Author { get; set; }
        [JsonProperty("ruleset_name")]
        public string RulesetName { get; set; }
        [JsonProperty("rule_name")]
        public string RuleName { get; set; }
        [JsonProperty("ruleset_id")]
        public string RulesetId { get; set; }
    }
}
