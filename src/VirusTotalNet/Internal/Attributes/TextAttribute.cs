using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Attributes
{
    [JsonObject("attribute")]
    public class TextAttribute
    {
        [JsonProperty("text")]
        public string Text { get; set; }
    }
}
