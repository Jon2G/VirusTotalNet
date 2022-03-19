using Newtonsoft.Json;
using System;

namespace VirusTotalNet.Internal.Objects.v3
{
    [Serializable, JsonObject("data")]
    public class DataObject<T>
    {
        [JsonProperty("type")]
        public string Type { get; set; }
        [JsonProperty("attributes")]
        public T Attributes { get; set; }
        public DataObject()
        {

        }
    }
}
