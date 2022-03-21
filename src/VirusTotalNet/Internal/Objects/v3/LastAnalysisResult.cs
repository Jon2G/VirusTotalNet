using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class LastAnalysisResult
    {
        [JsonProperty("category")]
        public string Category { get; set; }
        [JsonProperty("result")]
        public string Result { get; set; }
        [JsonProperty("method")]
        public string Method { get; set; }
        [JsonProperty("engine_name")]
        public string EngineName { get; set; }
    }
}
