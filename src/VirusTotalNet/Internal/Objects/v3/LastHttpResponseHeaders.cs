using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class LastHttpResponseHeaders
    {
        [JsonProperty("content-length")]
        public int ContentLength { get; set; }
        [JsonProperty("expires")]
        public int Expires { get; set; }
        [JsonProperty("content-encoding")]
        public string ContentEncoding { get; set; }
        [JsonProperty("set-cookie")]
        public string SetCookie { get; set; }
        [JsonProperty("strict-transport-security")]
        public string StrictTransportSecurity { get; set; }
        [JsonProperty("server")]
        public string Server { get; set; }
        [JsonProperty("x-xss-protection")]
        public int X_XSSProtection { get; set; }
        [JsonProperty("bfcache-opt-in")]
        public string BfcacheOptIn { get; set; }
        [JsonProperty("accept-ch")]
        public string AcceptCh { get; set; }
        [JsonProperty("cache-control")]
        public string CacheControl { get; set; }
        [JsonProperty("content-type")]
        public string ContentType { get; set; }
        [JsonProperty("x-frame-options")]
        public string XFrameOptions { get; set; }
    }
}
