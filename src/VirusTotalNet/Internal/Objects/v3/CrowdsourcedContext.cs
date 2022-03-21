using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;

namespace VirusTotalNet.Internal.Objects.v3
{
    [JsonObject]
    public class CrowdsourcedContext
    {
        [JsonProperty("source")]
        public string Source { get; set; }
        [JsonProperty("timestamp", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime WhoIsTimestamp { get; set; }
        [JsonProperty("detail")]
        public string Detail { get; set; }
        [JsonProperty("severity")]
        public string Severity { get; set; }
        [JsonProperty("title")]
        public string Title { get; set; }

        public CrowdsourcedContext()
        {

        }
    }
}
