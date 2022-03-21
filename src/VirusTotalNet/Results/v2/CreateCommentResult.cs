using Newtonsoft.Json;
using VirusTotalNet.ResponseCodes;

namespace VirusTotalNet.Results.v2
{
    public class CreateCommentResult : VirusTotalNet.Results.CreateCommentResult
    {
        [JsonProperty("response_code")]
        public CommentResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonProperty("verbose_msg")]
        public string VerboseMsg { get; set; }
    }
}