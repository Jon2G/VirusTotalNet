namespace VirusTotalNet.Results
{
    public abstract class FileReport
    {
        /// <summary>
        /// MD5 hash of the resource.
        /// </summary>
        public string MD5 { get; set; }

        /// <summary>
        /// Contains the scan id for this result.
        /// </summary>
        public virtual string ScanId { get; set; }

        /// <summary>
        /// SHA1 hash of the resource.
        /// </summary>
        public string SHA1 { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        public string SHA256 { get; set; }

    }
}