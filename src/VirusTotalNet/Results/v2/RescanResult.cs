using Newtonsoft.Json;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results.v2
{
    public class RescanResult : VirusTotalNet.Results.RescanResult
    {
        /// <summary>
        /// A unique link to this particular scan result.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// Id of the resource.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// The unique scan id of the resource.
        /// </summary>
        [JsonProperty("scan_id")]
        public override string ScanId { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string SHA256 { get; set; }

        [JsonProperty("response_code")]
        public RescanResponseCode ResponseCode { get; set; }
        [JsonProperty("type")]
        public string Type { get; set; }
    }
}