using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class PopularThreatClassification
    {
        [JsonProperty("suggested_threat_label")]
        public string SuggestedThreatLabel { get; set; }
        [JsonProperty("popular_threat_category")]
        public PopularThreatCategory[] PopularThreatCategory { get; set; }
        public PopularThreatName[] PopularThreatName { get; set; }
    }
}
