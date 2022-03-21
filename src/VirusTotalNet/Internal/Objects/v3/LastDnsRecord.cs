using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    [JsonObject]
    public class LastDnsRecord
    {
        [JsonProperty("type")]
        public string Type { get; set; }
        [JsonProperty("value")]
        public string Value { get; set; }
        [JsonProperty("ttl")]
        public int TTL { get; set; }
    }
}
