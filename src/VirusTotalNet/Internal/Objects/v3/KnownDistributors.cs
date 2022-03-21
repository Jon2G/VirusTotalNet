using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class KnownDistributors
    {
        [JsonProperty("filenames")]
        public string[] FileNames { get; set; }
        [JsonProperty("products")]
        public string[] Products { get; set; }
        [JsonProperty("distributors")]
        public string[] Distributors { get; set; }
        [JsonProperty("data_sources")]
        public string[] DataSources { get; set; }
    }
}
