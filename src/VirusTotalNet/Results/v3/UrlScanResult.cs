using Newtonsoft.Json;

namespace VirusTotalNet.Results.v3
{
    [JsonObject]
    public class UrlScanResult : VirusTotalNet.Results.UrlScanResult
    {
        [JsonProperty("id")]
        public override string ScanId { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        public UrlScanResult()
        {

        }
    }
}