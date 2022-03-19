using Newtonsoft.Json;

namespace VirusTotalNet.Results.v2
{
    public class FileReport : VirusTotalNet.Results.FileReport
    {

        [JsonProperty("scan_id")]
        public override string ScanId { get; set; }

    }
}