using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Internal.Objects.v3;

namespace VirusTotalNet.Results.v3
{
    public class UrlReport : VirusTotalNet.Results.UrlReport
    {
        [JsonProperty("last_modification_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastModification { get; set; }
        [JsonProperty("tags")]
        public string[] Tags { get; set; }
        [JsonProperty("last_analysis_stats")]
        public LastAnalysisStats LastAnalysisStats { get; set; }
        [JsonProperty("reputation")]
        public int Reputation { get; set; }
        [JsonProperty("last_analysis_results")]
        public LastAnalysisResults LastAnalysisResults { get; set; }
        [JsonProperty("times_submitted")]
        public int TimesSubmitted { get; set; }
        [JsonProperty("total_votes")]
        public TotalVotes TotalVotes { get; set; }
        [JsonProperty("redirection_chain")]
        public string[] RedirectionChain { get; set; }
        [JsonProperty("last_http_response_content_length")]
        public int LastHttpResponseContentLength { get; set; }
        [JsonProperty("last_http_response_headers")]
        public LastHttpResponseHeaders last_http_response_headers { get; set; }
        [JsonProperty("categories")]
        public Categories Categories { get; set; }
        [JsonProperty("title")]
        public string Title { get; set; }
        [JsonProperty("outgoing_links")]
        public string[] OutgoingLinks { get; set; }
    }
}