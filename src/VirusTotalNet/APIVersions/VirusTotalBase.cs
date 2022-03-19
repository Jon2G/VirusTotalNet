using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.Enums;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;
using VirusTotalNet.Interfaces;
using VirusTotalNet.Internal.Other;
using VirusTotalNet.Results;

namespace VirusTotalNet.APIVersions
{
    public abstract class VirusTotalBase : IVirusTotalAPI
    {
        protected readonly HttpClient _client;
        protected readonly HttpClientHandler _httpClientHandler;
        protected readonly Dictionary<string, string> _defaultValues;
        protected readonly JsonSerializer _serializer;
        protected abstract string _apiUrl { get; }

        /// <summary>
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
        public int FileSizeLimit { get; set; } = 33553369; //32 MB - 1063 = 33553369 it is the effective limit by virus total as it measures file size limit on the TOTAL request size, and not just the file content.

        /// <summary>
        /// The maximum size when using the large file API functionality (part of private API)
        /// </summary>
        public long LargeFileSizeLimit { get; set; } = 1024 * 1024 * 200; //200 MB

        /// <summary>
        /// The maximum size (in bytes) of comments.
        /// </summary>
        public int CommentSizeRestriction { get; set; } = 4096;

        /// <summary>
        /// The maximum number of resources you can rescan in one request.
        /// </summary>
        public int RescanBatchSizeLimit { get; set; } = 25;

        /// <summary>
        /// The maximum number of resources you can get file reports for in one request.
        /// </summary>
        public int FileReportBatchSizeLimit { get; set; } = 4;

        /// <summary>
        /// The maximum number of URLs you can get reports for in one request.
        /// </summary>
        public int UrlReportBatchSizeLimit { get; set; } = 4;

        /// <summary>
        /// The maximum number of URLs you can scan in one request.
        /// </summary>
        public int UrlScanBatchSizeLimit { get; set; } = 25;

        /// <summary>
        /// Set to false to use HTTP instead of HTTPS. HTTPS is used by default.
        /// </summary>
        public bool UseTLS { get; set; } = true;

        /// <summary>
        /// The user-agent to use when doing queries
        /// </summary>
        public string UserAgent
        {
            get => _client.DefaultRequestHeaders.UserAgent.ToString();
            set => _client.DefaultRequestHeaders.Add("User-Agent", value);
        }

        /// <summary>
        /// Get or set the proxy.
        /// </summary>
        public IWebProxy Proxy
        {
            get => _httpClientHandler.Proxy;
            set
            {
                _httpClientHandler.UseProxy = value != null;
                _httpClientHandler.Proxy = value;
            }
        }

        /// <summary>
        /// Get or set the timeout.
        /// </summary>
        public TimeSpan Timeout
        {
            get => _client.Timeout;
            set => _client.Timeout = value;
        }
        protected VirusTotalBase(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new ArgumentException("You have to set an API key.", nameof(apiKey));

            if (apiKey.Length < 64)
                throw new ArgumentException("API key is too short.", nameof(apiKey));

            _defaultValues = new Dictionary<string, string>(1);
            _defaultValues.Add("apikey", apiKey);

            _httpClientHandler = new HttpClientHandler();
            _httpClientHandler.AllowAutoRedirect = true;

            JsonSerializerSettings jsonSettings = new JsonSerializerSettings();
            jsonSettings.NullValueHandling = NullValueHandling.Ignore;
            jsonSettings.Formatting = Formatting.None;

            _serializer = JsonSerializer.Create(jsonSettings);

            _client = new HttpClient(_httpClientHandler);

            RestrictSizeLimits = true;
            RestrictNumberOfResources = true;
        }

        protected VirusTotalBase(string apiKey, JsonSerializerSettings settings) : this(apiKey)
        {
            if (settings is not null)
                _serializer = JsonSerializer.Create(settings);
        }
        protected void ValidateScanFileArguments(Stream stream, long fileSizeLimit, string filename)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream), "You must provide a stream that is not null");

            if (stream.Length <= 0)
                throw new ArgumentException("You must provide a stream with content", nameof(stream));

            if (RestrictSizeLimits && stream.Length > fileSizeLimit)
                throw new SizeLimitException(fileSizeLimit, stream.Length);

            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentException("You must provide a filename. Preferably the original filename.");
        }
        protected async Task<IEnumerable<T>> GetResponses<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpResponseMessage response = await SendRequest(url, method, content).ConfigureAwait(false);

            using (Stream responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                SaveResponse(responseStream);

                JToken token = JToken.Load(jsonTextReader);

                if (token.Type == JTokenType.Array)
                    return token.ToObject<List<T>>(_serializer);

                return new List<T> { token.ToObject<T>(_serializer) };
            }
        }

        protected async Task<T> GetResponse<T>(string url, HttpMethod method, HttpContent content)
        {
            HttpResponseMessage response = await SendRequest(url, method, content).ConfigureAwait(false);

            using (Stream responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                SaveResponse(responseStream);

                return _serializer.Deserialize<T>(jsonTextReader);
            }
        }

        protected async Task<HttpResponseMessage> SendRequest(string url, HttpMethod method, HttpContent content)
        {
            //We need this check because sometimes url is a full url and sometimes it is just an url segment
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                url = (UseTLS ? "https://" : "http://") + _apiUrl + url;

            HttpRequestMessage request = new HttpRequestMessage(method, url);
            request.Content = content;

            OnHTTPRequestSending?.Invoke(request);

            HttpResponseMessage response = await _client.SendAsync(request).ConfigureAwait(false);

            OnHTTPResponseReceived?.Invoke(response);

            if (response.StatusCode == HttpStatusCode.NoContent)
                throw new RateLimitException("You have reached the 4 requests pr. min. limit of VirusTotal");

            if (response.StatusCode == HttpStatusCode.Forbidden)
                throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");

            if (response.StatusCode == HttpStatusCode.RequestEntityTooLarge)
                throw new SizeLimitException(FileSizeLimit);

            if (response.StatusCode != HttpStatusCode.OK)
                throw new Exception("API gave error code " + response.StatusCode);

            if (string.IsNullOrWhiteSpace(response.Content.ToString()))
                throw new Exception("There were no content in the response.");

            return response;
        }

        protected void SaveResponse(Stream stream)
        {
            if (OnRawResponseReceived == null)
                return;

            using (MemoryStream ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                OnRawResponseReceived(ms.ToArray());
            }

            stream.Position = 0;
        }

        protected virtual HttpContent CreateApiPart()
        {
            HttpContent content = new StringContent(_defaultValues["apikey"]);
            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"apikey\""
            };
            return content;
        }

        protected HttpContent CreateFileContent(Stream stream, string fileName, bool includeSize = true)
        {
            StreamContent fileContent = new StreamContent(stream);

            ContentDispositionHeaderValue disposition = new ContentDispositionHeaderValue("form-data");
            disposition.Name = "\"file\"";
            disposition.FileName = "\"" + fileName + "\"";

            if (includeSize)
                disposition.Size = stream.Length;

            fileContent.Headers.ContentDisposition = disposition;
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            return fileContent;
        }

        protected HttpContent CreateURLEncodedContent(IDictionary<string, string> values)
        {
            return new CustomURLEncodedContent(_defaultValues.Concat(values));
        }
        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="filePath">The file to scan</param>
        public async Task ScanFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("The file was not found.", filePath);

            string filename = Path.GetFileName(filePath);

            using (Stream fs = File.OpenRead(filePath))
                await ScanFileAsync(fs, filename);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        public async Task<ScanResult> ScanFileAsync(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("The file was not found.", file.Name);

            using (Stream fs = file.OpenRead())
                return await ScanFileAsync(fs, file.Name).ConfigureAwait(false);
        }

        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public async Task<ScanResult> ScanFileAsync(byte[] file, string filename)
        {
            using (MemoryStream ms = new MemoryStream(file))
                return await ScanFileAsync(ms, filename).ConfigureAwait(false);
        }
        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="filePath">The file to scan</param>
        public async Task<ScanResult> ScanLargeFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("The file was not found.", filePath);

            string filename = Path.GetFileName(filePath);

            using (Stream fs = File.OpenRead(filePath))
                return await ScanLargeFileAsync(fs, filename);
        }

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// </summary>
        /// <param name="file">The file to scan</param>
        public async Task<ScanResult> ScanLargeFileAsync(FileInfo file)
        {
            if (!file.Exists)
                throw new FileNotFoundException("The file was not found.", file.Name);

            using (Stream fs = file.OpenRead())
                return await ScanLargeFileAsync(fs, file.Name);
        }

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="file">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public async Task<ScanResult> ScanLargeFileAsync(byte[] file, string filename)
        {
            using (MemoryStream ms = new MemoryStream(file))
                return await ScanLargeFileAsync(ms, filename);
        }
        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(FileInfo file)
        {
            return RescanFileAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(byte[] file)
        {
            return RescanFileAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        public Task<RescanResult> RescanFileAsync(Stream stream)
        {
            return RescanFileAsync(ResourcesHelper.GetResourceIdentifier(stream));
        }
        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(byte[] file)
        {
            return GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="file">The file you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(FileInfo file)
        {
            return GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(file));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="stream">The stream you want to get a report on.</param>
        public Task<FileReport> GetFileReportAsync(Stream stream)
        {
            return GetFileReportAsync(ResourcesHelper.GetResourceIdentifier(stream));
        }
        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<byte[]> files)
        {
            return GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
        /// </summary>
        /// <param name="files">The files you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<FileInfo> files)
        {
            return GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Gets a list of reports of the files.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
        /// </summary>
        /// <param name="streams">The streams you want to get reports on.</param>
        public Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<Stream> streams)
        {
            return GetFileReportsAsync(ResourcesHelper.GetResourceIdentifier(streams));
        }
        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<FileInfo> files)
        {
            return RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<byte[]> files)
        {
            return RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(files));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// </summary>
        public Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<Stream> streams)
        {
            return RescanFilesAsync(ResourcesHelper.GetResourceIdentifier(streams));
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urlList">The URLs to process.</param>
        public Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<Uri> urlList)
        {
            return ScanUrlsAsync(urlList.Select(x => x.ToString()));
        }
        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public Task<UrlScanResult> ScanUrlAsync(Uri url)
        {
            return ScanUrlAsync(url.ToString());
        }
        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public Task<UrlReport> GetUrlReportAsync(Uri url, bool scanIfNoReport = false)
        {
            return GetUrlReportAsync(url.ToString(), scanIfNoReport);
        }
        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public Task<IPReport> GetIPReportAsync(IPAddress ip)
        {
            return GetIPReportAsync(ip.ToString());
        }
        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public Task<DomainReport> GetDomainReportAsync(Uri domain)
        {
            return GetDomainReportAsync(domain.Host);
        }
        /// <summary>
        /// Retrieves a comment on a file.
        /// </summary>
        /// <param name="file">The file you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(byte[] file, DateTime? before = null)
        {
            return GetCommentAsync(ResourcesHelper.GetResourceIdentifier(file), before);
        }

        /// <summary>
        /// Retrieves a comment on a file.
        /// </summary>
        /// <param name="file">The file you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(FileInfo file, DateTime? before = null)
        {
            return GetCommentAsync(ResourcesHelper.GetResourceIdentifier(file), before);
        }
        /// <summary>
        /// Retrieves a comment from an URL.
        /// </summary>
        /// <param name="uri">The URL you wish to retrieve a comment from</param>
        /// <param name="before">TODO</param>
        public Task<CommentResult> GetCommentAsync(Uri uri, DateTime? before = null)
        {
            return GetCommentAsync(uri.ToString(), before);
        }
        /// <summary>
        /// Creates a comment on a file
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(byte[] file, string comment)
        {
            return CreateCommentAsync(ResourcesHelper.GetResourceIdentifier(file), comment);
        }

        /// <summary>
        /// Creates a comment on a file
        /// </summary>
        /// <param name="file">The file you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(FileInfo file, string comment)
        {
            return CreateCommentAsync(ResourcesHelper.GetResourceIdentifier(file), comment);
        }

        /// <summary>
        /// Creates a comment on an URL
        /// </summary>
        /// <param name="url">The URL you wish to create a comment on</param>
        /// <param name="comment">The comment you wish to add.</param>
        public Task<CreateCommentResult> CreateCommentAsync(Uri url, string comment)
        {
            return CreateCommentAsync(url.ToString(), comment);
        }
        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(Uri url)
        {
            return GetPublicUrlScanLink(url.ToString());
        }
        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urlList">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        public Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<Uri> urlList, bool scanIfNoReport = false)
        {
            return GetUrlReportsAsync(urlList.Select(x => x.ToString()), scanIfNoReport);
        }
        /// <summary>
        /// Gives you a link to a URL analysis.
        /// </summary>
        /// <returns>A link to VirusTotal that contains the report</returns>
        public string GetPublicUrlScanLink(string url)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL);

            return ResourcesHelper.NormalizeUrl($"www.virustotal.com/#/url/{ResourcesHelper.GetResourceIdentifier(url)}/detection", UseTLS);
        }
        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// </summary>
        public string GetPublicFileScanLink(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash);

            return ResourcesHelper.NormalizeUrl($"www.virustotal.com/#/file/{resource}/detection", UseTLS);
        }

        /// <summary>
        /// Gives you a link to a file analysis based on its hash.
        /// Note: This actually hashes the file - if you have the hash already, use the overload that takes in a string.
        /// </summary>
        public string GetPublicFileScanLink(FileInfo file)
        {
            if (file == null)
                throw new ArgumentNullException(nameof(file));

            if (!file.Exists)
                throw new FileNotFoundException("The file you provided does not exist.", file.FullName);

            return GetPublicFileScanLink(ResourcesHelper.GetResourceIdentifier(file));
        }
        public abstract Task<ScanResult> ScanFileAsync(Stream stream, string filename);
        public abstract Task<ScanResult> ScanLargeFileAsync(Stream stream, string filename);
        public abstract Task<RescanResult> RescanFileAsync(string resource);
        public abstract Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList);
        public abstract Task<FileReport> GetFileReportAsync(string resource);
        public abstract Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList);
        public abstract Task<UrlScanResult> ScanUrlAsync(string url);
        public abstract Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls);
        public abstract Task<UrlReport> GetUrlReportAsync(string url, bool scanIfNoReport = false);
        public abstract Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false);
        public abstract Task<IPReport> GetIPReportAsync(string ip);
        public abstract Task<DomainReport> GetDomainReportAsync(string domain);
        public abstract Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null);
        public abstract Task<CreateCommentResult> CreateCommentAsync(string resource, string comment);
    }
}
