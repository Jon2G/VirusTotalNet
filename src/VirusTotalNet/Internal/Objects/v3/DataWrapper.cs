using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class SimpleDataWrapper<T>
    {
        [JsonProperty("data", NullValueHandling = NullValueHandling.Ignore)]
        public T Data { get; set; }
    }
    public class DataWrapper<T>
    {
        [JsonProperty("data", NullValueHandling = NullValueHandling.Ignore)]
        public DataObject<T> Data { get; set; }
    }
    public class DataWrapper
    {
        [JsonProperty("data", NullValueHandling = NullValueHandling.Ignore)]
        public DataObject Data { get; set; }
    }
}
