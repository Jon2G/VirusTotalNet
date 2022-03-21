using Newtonsoft.Json;
using System;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class Link
    {
        [JsonProperty("self")]
        public Uri Self { get; set; }
    }
}
