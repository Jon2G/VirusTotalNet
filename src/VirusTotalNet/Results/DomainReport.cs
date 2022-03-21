using Newtonsoft.Json;
using System;

namespace VirusTotalNet.Results
{
    public abstract class DomainReport
    {
        [JsonProperty("whois")]
        public string WhoIs { get; set; }

        public virtual DateTime WhoIsTimestamp { get; set; }

    }
}