using Newtonsoft.Json;

namespace VirusTotalNet.Results
{
    public abstract class UrlScanResult
    {
        /// <summary>
        /// The unique scan id of the resource.
        /// </summary>
        [JsonProperty("scan_id")]
        public virtual string ScanId { get; set; }
    }
}