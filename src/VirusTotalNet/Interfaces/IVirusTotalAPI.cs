using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.Results;

namespace VirusTotalNet.Interfaces
{
    public interface IVirusTotalAPI
    {/// <summary>
     /// Occurs when the raw JSON response is received from VirusTotal.
     /// </summary>
        public event Action<byte[]> OnRawResponseReceived;

        /// <summary>
        /// Occurs just before we send a request to VirusTotal.
        /// </summary>
        public event Action<HttpRequestMessage> OnHTTPRequestSending;

        /// <summary>
        /// Occurs right after a response has been received from VirusTotal.
        /// </summary>
        public event Action<HttpResponseMessage> OnHTTPResponseReceived;

        /// <summary>
        /// When true, we check the file size before uploading it to Virus Total. The file size restrictions are based on the Virus Total public API 2.0 documentation.
        /// </summary>
        public bool RestrictSizeLimits { get; set; }

        /// <summary>
        /// When true, we check the number of resources that are submitted to Virus Total. The limits are according to Virus Total public API 2.0 documentation.
        /// </summary>
        public bool RestrictNumberOfResources { get; set; }

        /// <summary>
        /// The maximum size (in bytes) that the Virus Total public API 2.0 supports for file uploads.
        /// </summary>
        public int FileSizeLimit { get; set; }

        /// <summary>
        /// The maximum size when using the large file API functionality (part of private API)
        /// </summary>
        public long LargeFileSizeLimit { get; set; }

        /// <summary>
        /// The maximum size (in bytes) of comments.
        /// </summary>
        public int CommentSizeRestriction { get; set; }

        /// <summary>
        /// The maximum number of resources you can rescan in one request.
        /// </summary>
        public int RescanBatchSizeLimit { get; set; }

        /// <summary>
        /// The maximum number of resources you can get file reports for in one request.
        /// </summary>
        public int FileReportBatchSizeLimit { get; set; }

        /// <summary>
        /// The maximum number of URLs you can get reports for in one request.
        /// </summary>
        public int UrlReportBatchSizeLimit { get; set; }

        /// <summary>
        /// The maximum number of URLs you can scan in one request.
        /// </summary>
        public int UrlScanBatchSizeLimit { get; set; }

        /// <summary>
        /// Set to false to use HTTP instead of HTTPS. HTTPS is used by default.
        /// </summary>
        public bool UseTLS { get; set; }

        /// <summary>
        /// The user-agent to use when doing queries
        /// </summary>
        public string UserAgent
        {
            get;
            set;
        }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        public IWebProxy Proxy
        {
            get;
            set;
        }

        /// <summary>
        /// Get or set the timeout.
        /// </summary>
        public TimeSpan Timeout
        {
            get;
            set;
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="filePath">The file to scan</param>
        public Task ScanFileAsync(string filePath);

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        public Task<ScanResult> ScanFileAsync(FileInfo file);

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public Task<ScanResult> ScanFileAsync(byte[] file, string filename);

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="stream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public Task<ScanResult> ScanFileAsync(Stream stream, string filename);

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="filePath">The file to scan</param>
        public Task<ScanResult> ScanLargeFileAsync(string filePath);

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        public Task<ScanResult> ScanLargeFileAsync(FileInfo file);

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public Task<ScanResult> ScanLargeFileAsync(byte[] file, string filename);

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="stream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public Task<ScanResult> ScanLargeFileAsync(Stream stream, string filename);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(FileInfo file);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(byte[] file);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(Stream stream);

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
        public Task<RescanResult> RescanFileAsync(string resource);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<FileInfo> files);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<byte[]> files);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<Stream> streams);

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
        /// Note: You can only request a maximum of 25 rescans at the time.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.</param>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList);

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(byte[] file);

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(FileInfo file);

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="stream">The stream you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(Stream stream);

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(string resource);

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<byte[]> files);

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<FileInfo> files);

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
        /// </summary>
        /// <param name="streams">The streams you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<Stream> streams);

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList);

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public Task<UrlScanResult> ScanUrlAsync(string url);

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public Task<UrlScanResult> ScanUrlAsync(Uri url);

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urls">The URLs to process.</param>
        public Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls);

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The URLs to process.</param>
        public Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<Uri> urlList);

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public Task<UrlReport> GetUrlReportAsync(string url, bool scanIfNoReport = false);

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public Task<UrlReport> GetUrlReportAsync(Uri url, bool scanIfNoReport = false);

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urls">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        public Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false);

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        public Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<Uri> urlList, bool scanIfNoReport = false);

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public Task<IPReport> GetIPReportAsync(string ip);

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public Task<IPReport> GetIPReportAsync(IPAddress ip);

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public Task<DomainReport> GetDomainReportAsync(string domain);

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public Task<DomainReport> GetDomainReportAsync(Uri domain);

        /// <summary>
        /// Retrieves a comment on a file.
        /// </summary>
        /// <param name="file">The file you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(byte[] file, DateTime? before = null);

        /// <summary>
        /// Retrieves a comment on a file.
        /// </summary>
        /// <param name="file">The file you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(FileInfo file, DateTime? before = null);

        /// <summary>
        /// Retrieves a comment from an URL.
        /// </summary>
        /// <param name="uri">The URL you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(Uri uri, DateTime? before = null);

        /// <summary>
        /// Retrieves a comment on a resource.
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null);

        /// <summary>
        /// Creates a comment on a file
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(byte[] file, string comment);

        /// <summary>
        /// Creates a comment on a file
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(FileInfo file, string comment);

        /// <summary>
        /// Creates a comment on an URL
        /// </summary>
        /// <param name="url">The URL you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(Uri url, string comment);

        /// <summary>
        /// Creates a comment on a resource
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(string resource, string comment);

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        public string GetPublicFileScanLink(string resource);

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// Note: This actually hashes the file - if you have the hash already, use the overload that takes in a string.
        /// </summary>
        public string GetPublicFileScanLink(FileInfo file);

        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(string url);

        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(Uri url);

    }
}
