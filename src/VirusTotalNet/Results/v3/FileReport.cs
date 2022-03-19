using Newtonsoft.Json;

namespace VirusTotalNet.Results.v3
{
    public class FileReport : VirusTotalNet.Results.FileReport
    {
        /// <summary>
        /// Contains the scan id for this result.
        /// </summary>
        [JsonProperty("id")]
        public override string ScanId { get; set; }

    }
}