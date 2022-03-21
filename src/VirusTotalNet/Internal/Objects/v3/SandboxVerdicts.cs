using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class SandboxVerdicts
    {
        [JsonProperty("Lastline")]
        public Lastline Lastline { get; set; }
    }
}
