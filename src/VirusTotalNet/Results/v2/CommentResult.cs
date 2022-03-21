using Newtonsoft.Json;
using System.Collections.Generic;
using VirusTotalNet.Objects;

namespace VirusTotalNet.Results.v2
{
    public class CommentResult : VirusTotalNet.Results.CommentResult
    {
        /// <summary>
        /// A list of comments on the resource
        /// </summary>
        public List<UserComment> Comments { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}