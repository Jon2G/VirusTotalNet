using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Internal.Objects.v3;

namespace VirusTotalNet.Results.v3
{
    public class DomainReport : VirusTotalNet.Results.DomainReport
    {
        [JsonProperty("registrar")]
        public string Registrar { get; set; }
        [JsonProperty("last_dns_records")]
        public LastDnsRecord[] LastDnsRecords { get; set; }
        [JsonProperty("tags")]
        public string[] Tags { get; set; }
        //[JsonProperty("popularity_ranks")]
        //public object PopularityRanks { get; set; }
        [JsonProperty("last_analysis_stats")]
        public LastAnalysisStats LastAnalysisStats { get; set; }
        [JsonProperty("reputation")]
        public int Reputation { get; set; }
        [JsonProperty("last_analysis_results")]
        public LastAnalysisResults LastAnalysisResults { get; set; }

        [JsonProperty("last_modification_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastModification { get; set; }
        [JsonProperty("categories")]
        public Categories Categories { get; set; }
        [JsonProperty("total_votes")]
        public TotalVotes TotalVotes { get; set; }

        [JsonProperty("whois_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public override DateTime WhoIsTimestamp { get; set; }

        [JsonProperty("last_update_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastUpdate { get; set; }

        public DomainReport()
        {

        }
    }
}