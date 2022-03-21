using Newtonsoft.Json;

namespace VirusTotalNet.Results
{
    public abstract class IPReport
    {
        [JsonProperty("asn")]
        public int ASN { get; set; }
        [JsonProperty("country")]
        public string Country { get; set; }
        [JsonProperty("network")]
        public string Network { get; set; }




    }
}