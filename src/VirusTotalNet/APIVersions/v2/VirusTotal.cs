using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.APIVersions;
using VirusTotalNet.Enums;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;
using VirusTotalNet.Internal.Objects.v2;
using VirusTotalNet.Results;
using FileReport = VirusTotalNet.Results.FileReport;

// ReSharper disable once CheckNamespace
namespace VirusTotalNet.v2
{
    public class VirusTotal : VirusTotalBase
    {
        protected override string _apiUrl => "www.virustotal.com/vtapi/v2/";

        /// <param name="apiKey">The API key you got from Virus Total</param>
        public VirusTotal(string apiKey) : base(apiKey)
        {

        }

        internal VirusTotal(string apiKey, JsonSerializerSettings settings) : base(apiKey, settings)
        {

        }


        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="stream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public override Task<ScanResult> ScanFileAsync(Stream stream, string filename)
        {
            ValidateScanFileArguments(stream, FileSizeLimit, filename);

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateApiPart());
            multi.Add(CreateFileContent(stream, filename));

            //https://www.virustotal.com/vtapi/v2/file/scan
            return GetResponse<ScanResult>("file/scan", HttpMethod.Post, multi);
        }

        /// <summary>
        /// Scan a large file. The difference between <see cref="ScanFileAsync(FileInfo)"/> and this method, is that this method sends 2 requests, and it is part of the private VT API, so you need an API key with large file upload support.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="stream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public override async Task<ScanResult> ScanLargeFileAsync(Stream stream, string filename)
        {
            ValidateScanFileArguments(stream, LargeFileSizeLimit, filename);

            if (stream.Length <= FileSizeLimit)
                throw new ArgumentException($"Please use the ScanFileAsync() method for files smaller than {FileSizeLimit} bytes");

            //https://www.virustotal.com/vtapi/v2/file/scan/upload_url
            LargeFileUpload uploadUrlObj = await GetResponse<LargeFileUpload>("file/scan/upload_url?apikey=" + _defaultValues["apikey"], HttpMethod.Get, null);

            if (string.IsNullOrEmpty(uploadUrlObj.UploadUrl))
                throw new Exception("Something when wrong while getting the upload url. Are you using an API key with support for this request?");

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateFileContent(stream, filename, false)); //The big file upload API does not like it when multi-part uploads contain the size field

            return await GetResponse<ScanResult>(uploadUrlObj.UploadUrl, HttpMethod.Post, multi);
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
        public override Task<RescanResult> RescanFileAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);

            //https://www.virustotal.com/vtapi/v2/file/rescan
            return GetResponse<RescanResult>("file/rescan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
        /// Note: You can only request a maximum of 25 rescans at the time.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.</param>
        public override Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList)
        {
            resourceList = ResourcesHelper.ValidateResourcea(resourceList, ResourceType.AnyHash);

            string[] resources = resourceList as string[] ?? resourceList.ToArray();

            if (RestrictNumberOfResources && resources.Length > RescanBatchSizeLimit)
                throw new ResourceLimitException($"Too many resources. There is a maximum of {RescanBatchSizeLimit} resources at the time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(",", resources));

            //https://www.virustotal.com/vtapi/v2/file/rescan
            return GetResponses<RescanResult>("file/rescan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public override Task<FileReport> GetFileReportAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.ScanId);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);

            //https://www.virustotal.com/vtapi/v2/file/report
            return GetResponse<FileReport>("file/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        public override Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList)
        {
            resourceList = ResourcesHelper.ValidateResourcea(resourceList, ResourceType.AnyHash | ResourceType.ScanId);

            string[] resources = resourceList as string[] ?? resourceList.ToArray();

            if (RestrictNumberOfResources && resources.Length > FileReportBatchSizeLimit)
                throw new ResourceLimitException($"Too many hashes. There is a maximum of {FileReportBatchSizeLimit} resources at the same time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(",", resources));

            //https://www.virustotal.com/vtapi/v2/file/report
            return GetResponses<FileReport>("file/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public override Task<UrlScanResult> ScanUrlAsync(string url)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", url);

            //https://www.virustotal.com/vtapi/v2/url/scan
            return GetResponse<UrlScanResult>("url/scan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urls">The URLs to process.</param>
        public override Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls)
        {
            urls = ResourcesHelper.ValidateResourcea(urls, ResourceType.URL);

            string[] urlCast = urls as string[] ?? urls.ToArray();

            if (RestrictNumberOfResources && urlCast.Length > UrlScanBatchSizeLimit)
                throw new ResourceLimitException($"Too many URLs. There is a maximum of {UrlScanBatchSizeLimit} URLs at the same time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", string.Join(Environment.NewLine, urlCast));

            //https://www.virustotal.com/vtapi/v2/url/scan
            return GetResponses<UrlScanResult>("url/scan", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public override Task<UrlReport> GetUrlReportAsync(string url, bool scanIfNoReport = false)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL | ResourceType.ScanId);

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", url);

            //Optional
            if (scanIfNoReport)
                values.Add("scan", "1");

            //Output
            return GetResponse<UrlReport>("url/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urls">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        public override Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false)
        {
            urls = ResourcesHelper.ValidateResourcea(urls, ResourceType.URL);

            string[] urlCast = urls as string[] ?? urls.ToArray();

            if (RestrictNumberOfResources && urlCast.Length > UrlReportBatchSizeLimit)
                throw new ResourceLimitException($"Too many URLs. There is a maximum of {UrlReportBatchSizeLimit} urls at the time.");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", string.Join(Environment.NewLine, urlCast));

            //Optional
            if (scanIfNoReport)
                values.Add("scan", "1");

            //Output
            return GetResponses<UrlReport>("url/report", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public override Task<IPReport> GetIPReportAsync(string ip)
        {
            ip = ResourcesHelper.ValidateResourcea(ip, ResourceType.IP);

            return GetResponse<IPReport>("ip-address/report?apikey=" + _defaultValues["apikey"] + "&ip=" + ip, HttpMethod.Get, null);
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public override Task<DomainReport> GetDomainReportAsync(string domain)
        {
            domain = ResourcesHelper.ValidateResourcea(domain, ResourceType.Domain);

            //Hack because VT thought it was a good idea to have this API call as GET
            return GetResponse<DomainReport>("domain/report?apikey=" + _defaultValues["apikey"] + "&domain=" + domain, HttpMethod.Get, null);
        }

        /// <summary>
        /// Retrieves a comment on a resource.
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="before">TODO</param>
        public override Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.URL);

            //TODO: before

            //https://www.virustotal.com/vtapi/v2/comments/get
            return GetResponse<CommentResult>("comments/get?apikey=" + _defaultValues["apikey"] + "&resource=" + resource, HttpMethod.Get, null);
        }

        /// <summary>
        /// Creates a comment on a resource
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="comment">The comment you wish to add.</param>
        public override Task<CreateCommentResult> CreateCommentAsync(string resource, string comment)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.URL);

            if (string.IsNullOrWhiteSpace(comment))
                throw new ArgumentException("Comment must not be null or whitespace", nameof(comment));

            if (RestrictSizeLimits && comment.Length > CommentSizeRestriction)
                throw new ArgumentOutOfRangeException(nameof(comment), $"Your comment is larger than the maximum size of {CommentSizeRestriction / 1024} KB");

            //Required
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("resource", resource);
            values.Add("comment", comment);

            //https://www.virustotal.com/vtapi/v2/comments/put
            return GetResponse<CreateCommentResult>("comments/put", HttpMethod.Post, CreateURLEncodedContent(values));
        }
    }
}