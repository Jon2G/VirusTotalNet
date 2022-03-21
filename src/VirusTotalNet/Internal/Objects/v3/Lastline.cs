using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class Lastline
    {
        [JsonProperty("category")]
        public string Category { get; set; }
        [JsonProperty("sandbox_name")]
        public string SandboxName { get; set; }
        [JsonProperty("malware_classification")]
        public string[] MalwareClassification { get; set; }
    }
}
