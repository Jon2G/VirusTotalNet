using Newtonsoft.Json;
using System;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results.v2
{
    public class UrlScanResult : VirusTotalNet.Results.UrlScanResult
    {
        public string Url { get; set; }

        [JsonProperty("scan_date")]
        public DateTime ScanDate { get; set; }

        /// <summary>
        /// A unique link to this particular scan result.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// The resource.
        /// </summary>
        public string Resource { get; set; }

        [JsonProperty("response_code")]
        public UrlScanResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}