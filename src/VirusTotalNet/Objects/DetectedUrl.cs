using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;

namespace VirusTotalNet.Objects
{
    public class DetectedUrl
    {
        public string Url { get; set; }

        public int Positives { get; set; }

        public int Total { get; set; }

        [JsonProperty("scan_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime ScanDate { get; set; }
    }
}