using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class EC
    {
        [JsonProperty("oid")]
        public string OID { get; set; }
        [JsonProperty("pub")]
        public string Pub { get; set; }
    }
}
