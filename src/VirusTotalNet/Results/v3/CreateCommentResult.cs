using Newtonsoft.Json;
using System;
using VirusTotalNet.Internal.DateTimeParsers;
using VirusTotalNet.Internal.Objects.v3;

namespace VirusTotalNet.Results.v3
{
    public class CreateCommentResult : VirusTotalNet.Results.CreateCommentResult
    {
        [JsonProperty("date", NullValueHandling = NullValueHandling.Ignore)]
        [JsonConverter(typeof(UnixTimeConverter))]
        public DateTime Date { get; set; }
        [JsonProperty("text")]
        public string Text { get; set; }
        [JsonProperty("votes")]
        public Votes Votes { get; set; }
        [JsonProperty("html")]
        public string Html { get; set; }
        [JsonProperty("tags")]
        public string[] Tags { get; set; }
    }
}