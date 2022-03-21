using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class Trid
    {
        [JsonProperty("file_type")]
        public string FileType { get; set; }
        [JsonProperty("probability")]
        public float Probability { get; set; }
    }
}
