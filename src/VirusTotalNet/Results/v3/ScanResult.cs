using Newtonsoft.Json;

namespace VirusTotalNet.Results.v3
{
    public class ScanResult : VirusTotalNet.Results.ScanResult
    {
        [JsonProperty("id")]
        public override string ScanId { get; set; }
        [JsonProperty("type")]
        public string Type { get; set; }
    }
}