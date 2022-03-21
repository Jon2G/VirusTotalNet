using Newtonsoft.Json;
using System;

namespace VirusTotalNet.Internal.Objects.v3
{
    [Serializable, JsonObject("data")]
    public class DataObject
    {
        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)]
        public string Type { get; set; }
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public string Id { get; set; }
        [JsonProperty("links", NullValueHandling = NullValueHandling.Ignore)]
        public Link Self { get; set; }

        public DataObject()
        {

        }
    }
    public class DataObject<T> : DataObject
    {
        [JsonProperty("attributes", NullValueHandling = NullValueHandling.Ignore)]
        public T Attributes { get; set; }
        public DataObject()
        {

        }
    }
}
