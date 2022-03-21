using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class LastAnalysisStats
    {
        [JsonProperty("harmless")]
        public int Harmless { get; set; }
        [JsonProperty("malicious")]
        public int Malicious { get; set; }
        [JsonProperty("suspicious")]
        public int Suspicious { get; set; }
        [JsonProperty("undetected")]
        public int Undetected { get; set; }
        [JsonProperty("timeout")]
        public int Timeout { get; set; }
    }
}
