using Newtonsoft.Json;

namespace VirusTotalNet.Results.v3
{
    public class RescanResult : VirusTotalNet.Results.RescanResult
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        /// <summary>
        /// The unique scan id of the resource.
        /// </summary>
        [JsonProperty("id")]
        public override string ScanId { get; set; }
    }
}