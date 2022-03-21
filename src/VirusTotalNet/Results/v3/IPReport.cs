using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Internal.Objects.v3;

namespace VirusTotalNet.Results.v3
{
    public class IPReport : VirusTotalNet.Results.IPReport
    {
        [JsonProperty("regional_internet_registry")]
        public string RegionalInternetRegistry { get; set; }
        [JsonProperty("jarm")]
        public string Jarm { get; set; }
        [JsonProperty("last_https_certificate_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastHttpsCertificateDate { get; set; }
        [JsonProperty("tags")]
        public string[] Tags { get; set; }
        [JsonProperty("last_analysis_stats")]
        public LastAnalysisStats LastAnalysisStats { get; set; }
        [JsonProperty("last_analysis_results")]
        public LastAnalysisResult LastAnalysisResult { get; set; }
        [JsonProperty("crowdsourced_context")]
        public CrowdsourcedContext[] CrowdsourcedContext { get; set; }
        [JsonProperty("as_owner")]
        public string AsOwner { get; set; }

        public IPReport()
        {

        }
    }
}