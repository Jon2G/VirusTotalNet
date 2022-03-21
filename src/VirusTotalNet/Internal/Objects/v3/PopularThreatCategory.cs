using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class PopularThreatCategory
    {
        [JsonProperty("count")]
        public int Count { get; set; }
        [JsonProperty("value")]
        public string Value { get; set; }
    }
}
