using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class PublicKey
    {
        [JsonProperty("algorithm")]
        public string Algorithm { get; set; }
        [JsonProperty("ec")]
        public EC EC { get; set; }
    }
}
