using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Internal.Objects.v3;

namespace VirusTotalNet.Results.v3
{
    public class FileReport : VirusTotalNet.Results.FileReport
    {
        /// <summary>
        /// Contains the scan id for this result.
        /// </summary>
        [JsonProperty("id")]
        public override string ScanId { get; set; }
        [JsonProperty("type_description")]
        public string TypeDescription { get; set; }
        [JsonProperty("tlsh")]
        public string TLSH { get; set; }
        [JsonProperty("trid")]
        public Trid[] Trid { get; set; }
        [JsonProperty("antiy_info")]
        public string AntiyInfo { get; set; }
        [JsonProperty("crowdsourced_yara_results")]
        public CrowdsourcedYaraResult[] CrowdsourcedYaraResult { get; set; }
        [JsonProperty("names")]
        public string[] Names { get; set; }
        [JsonProperty("last_modification_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastModification { get; set; }
        [JsonProperty("type_tag")]
        public string TypeTag { get; set; }
        [JsonProperty("times_submitted")]
        public int TimesSubmitted { get; set; }
        [JsonProperty("total_votes")]
        public TotalVotes TotalVotes { get; set; }
        [JsonProperty("size")]
        public long Size { get; set; }
        [JsonProperty("popular_threat_classification")]
        public PopularThreatClassification PopularThreatClassification { get; set; }
        [JsonProperty("last_submission_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastSubmission { get; set; }
        [JsonProperty("known_distributors")]
        public KnownDistributors KnownDistributors { get; set; }
        [JsonProperty("meaningful_name")]
        public string MeaningfulName { get; set; }
        [JsonProperty("sandbox_verdicts")]
        public SandboxVerdicts SandboxVerdicts { get; set; }
        [JsonProperty("OS X Sandbox")]
        public OSXSandbox OSXSandbox { get; set; }
        [JsonProperty("type_extension")]
        public string TypeExtension { get; set; }
        [JsonProperty("tags")]
        public string[] Tags { get; set; }
        [JsonProperty("last_analysis_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime LastAnalysis { get; set; }
        [JsonProperty("unique_sources")]
        public int UniqueSources { get; set; }
        [JsonProperty("first_submission_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime FirstSubmission { get; set; }
        [JsonProperty("ssdeep")]
        public string SSDeep { get; set; }
        [JsonProperty("magic")]
        public string Magic { get; set; }
        [JsonProperty("last_analysis_stats")]
        public LastAnalysisStats LastAnalysisStats { get; set; }
        [JsonProperty("reputation")]
        public int Reputation { get; set; }
        [JsonProperty("last_analysis_results")]
        public LastAnalysisResults LastAnalysisResults { get; set; }
        [JsonProperty("first_seen_itw_date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime FirstSeenITWDate { get; set; }
    }
}