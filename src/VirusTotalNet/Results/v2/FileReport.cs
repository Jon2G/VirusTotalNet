using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results.v2
{
    public class FileReport : VirusTotalNet.Results.FileReport
    {

        [JsonProperty("scan_id")]
        public override string ScanId { get; set; }
        /// <summary>
        /// A permanent link that points to this specific scan.
        /// </summary>
        public string Permalink { get; set; }

        /// <summary>
        /// How many engines flagged this resource.
        /// </summary>
        public int Positives { get; set; }
        /// <summary>
        /// Contains the id of the resource. Can be a SHA256, MD5 or other hash type.
        /// </summary>
        public string Resource { get; set; }

        /// <summary>
        /// The date the resource was last scanned.
        /// </summary>
        [JsonProperty("scan_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime ScanDate { get; set; }
        /// <summary>
        /// The scan results from each engine.
        /// </summary>
        public Dictionary<string, ScanEngine> Scans { get; set; }
        /// <summary>
        /// How many engines scanned this resource.
        /// </summary>
        public int Total { get; set; }
        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        [JsonProperty("response_code")]
        public FileReportResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
        /// <summary>
        /// Contains the scan type for this result.
        /// </summary>
        [JsonProperty("type")]
        public string Type { get; set; }

    }
}