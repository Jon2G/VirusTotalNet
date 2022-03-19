using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    internal class LargeFileUpload
    {
        [JsonProperty("data")]
        public string UploadUrl { get; set; }
    }
}