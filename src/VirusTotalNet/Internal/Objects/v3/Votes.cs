using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class Votes
    {
        [JsonProperty("positive")]
        public int Positive { get; set; }
        [JsonProperty("abuse")]
        public int Abuse { get; set; }
        [JsonProperty("negative")]
        public int Negative { get; set; }
    }
}
