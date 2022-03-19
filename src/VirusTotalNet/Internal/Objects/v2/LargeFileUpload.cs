using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v2
{
    internal class LargeFileUpload
    {
        [JsonProperty("upload_url")]
        public string UploadUrl { get; set; }
    }
}