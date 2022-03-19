using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using VirusTotalNet.APIVersions;
using VirusTotalNet.Enums;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;
using VirusTotalNet.Internal.Attributes;
using VirusTotalNet.Internal.Objects.v3;
using VirusTotalNet.Results;
using FileReport = VirusTotalNet.Results.FileReport;

namespace VirusTotalNet.v3
{
    public class VirusTotal : VirusTotalBase
    {
        protected override string _apiUrl => "www.virustotal.com/api/v3/";

        /// <param name="apiKey">The API key you got from Virus Total</param>
        public VirusTotal(string apiKey) : base(apiKey)
        {

        }

        internal VirusTotal(string apiKey, JsonSerializerSettings settings) : base(apiKey, settings)
        {

        }
        protected override HttpContent CreateApiPart()
        {
            HttpContent content = new StringContent(_defaultValues["apikey"]);
            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"x-apikey\""
            };
            return content;
        }

        protected HttpContent CreateAcceptJsonPart()
        {
            HttpContent content = new StringContent("application/json");
            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"Accept\""
            };
            return content;
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

            //https://www.virustotal.com/api/v3/files
            return GetResponse<ScanResult>("files", HttpMethod.Post, multi);
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

            //https://www.virustotal.com/api/v3/files/upload_url
            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());

            LargeFileUpload uploadUrlObj = await GetResponse<LargeFileUpload>("files/upload_url", HttpMethod.Get, multi);

            if (string.IsNullOrEmpty(uploadUrlObj.UploadUrl))
                throw new Exception("Something when wrong while getting the upload url. Are you using an API key with support for this request?");

            multi = new MultipartFormDataContent();
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

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());

            //https://www.virustotal.com/api/v3/files/{id}/analyse
            return GetResponse<RescanResult>($"file/{resource}/analyse", HttpMethod.Post, multi);
        }

        /// <summary>
        /// Batch file rescan is deprecated on API v3, this will send as many requests as the number of resources.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// Note: Before requesting a rescan you should retrieve the latest report on the files.
        /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
        /// Note: You can only request a maximum of 25 rescans at the time.
        /// </summary>
        /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.</param>
        [Obsolete("Batch file rescan is deprecated on API v3, this will send as many requests as the number of resources.")]
#pragma warning disable CS0809 // Obsolete member overrides non-obsolete member
        public override Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            return
                Task.Run(() =>
                resourceList.Select(x => RescanFileAsync(x).GetAwaiter().GetResult()));
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public override Task<FileReport> GetFileReportAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.ScanId);

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());

            //https://www.virustotal.com/api/v3/files/{id}
            return GetResponse<FileReport>("file/" + resource, HttpMethod.Post, multi);
        }

        /// <summary>
        /// Batch file report is deprecated on API v3, this will send as many requests as the number of resources.
        /// Gets the report of the file represented by its hash or scan ID.
        /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
        /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
        /// </summary>
        /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
        [Obsolete("Batch file report is deprecated on API v3, this will send as many requests as the number of resources.")]
#pragma warning disable CS0809 // Obsolete member overrides non-obsolete member
        public override Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            return
                Task.Run(() =>
                    resourceList.Select(x => GetFileReportAsync(x).GetAwaiter().GetResult()));
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
            MultipartContent multi = new MultipartFormDataContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());
            multi.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            HttpContent content = new StringContent($"url={url}");
            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("application/x-www-form-urlencoded")
            {
                Name = "application/x-www-form-urlencoded"
            };
            multi.Add(content);
            IDictionary<string, string> values = new Dictionary<string, string>();
            values.Add("url", url);

            //https://www.virustotal.com/api/v3/urls
            return GetResponse<UrlScanResult>("urls", HttpMethod.Post, CreateURLEncodedContent(values));
        }

        /// <summary>
        /// Batch url scan is deprecated on API v3, this will send as many requests as the number of urls.
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urls">The URLs to process.</param>
        [Obsolete("Batch url scan is deprecated on API v3, this will send as many requests as the number of urls.")]
#pragma warning disable CS0809 // Obsolete member overrides non-obsolete member
        public override Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            return
                Task.Run(() =>
                    urls.Select(x => ScanUrlAsync(x).GetAwaiter().GetResult()));
        }

        /// <summary>
        /// Gets a scan report from an URL
        /// </summary>
        /// <param name="url">The URL you wish to get the report on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
        public override async Task<UrlReport> GetUrlReportAsync(string url, bool scanIfNoReport = false)
        {
            //https://www.virustotal.com/api/v3/urls/{id}
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL | ResourceType.ScanId);
            MultipartContent multi = new MultipartContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());
            var report = await GetResponse<UrlReport>($"/urls/{HttpUtility.UrlEncode(url)}", HttpMethod.Get, multi);
            if (scanIfNoReport && report.Total <= 0)
            {
                await ScanUrlAsync(url);
                report = await GetUrlReportAsync(url, false);
            }
            return report;
        }

        /// <summary>
        /// Batch url report is deprecated on API v3, this will send as many requests as the number of urls.
        /// Gets a scan report from a list of URLs
        /// </summary>
        /// <param name="urls">The URLs you wish to get the reports on.</param>
        /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
        [Obsolete("Batch url report is deprecated on API v3, this will send as many requests as the number of urls.")]
#pragma warning disable CS0809 // Obsolete member overrides non-obsolete member
        public override Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            return
                Task.Run(() =>
                    urls.Select(x => GetUrlReportAsync(x, scanIfNoReport).GetAwaiter().GetResult()));
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public override Task<IPReport> GetIPReportAsync(string ip)
        {
            //https://www.virustotal.com/api/v3/ip_addresses/{ip}
            MultipartContent multi = new MultipartContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());
            ip = ResourcesHelper.ValidateResourcea(ip, ResourceType.IP);
            return GetResponse<IPReport>($"ip_addresses/{ip}", HttpMethod.Get, multi);
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public override Task<DomainReport> GetDomainReportAsync(string domain)
        {
            MultipartContent multi = new MultipartContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());
            domain = ResourcesHelper.ValidateResourcea(domain, ResourceType.Domain);
            //https://www.virustotal.com/api/v3/domains/{domain}
            return GetResponse<DomainReport>($"domains/{domain}", HttpMethod.Get, multi);
        }

        /// <summary>
        /// Retrieves a comment on a resource.
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="before">TODO:Date has no effect!</param>
        public override Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.IP | ResourceType.URL | ResourceType.Domain);
            MultipartContent multi = new MultipartContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());


            //TODO: before

            //https://www.virustotal.com/api/v3/comments
            return GetResponse<CommentResult>($"comments/{resource}", HttpMethod.Get, multi);
        }

        /// <summary>
        /// Creates a comment on a resource
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="comment">The comment you wish to add.</param>
        public override Task<CreateCommentResult> CreateCommentAsync(string resource, string comment)
        {
            string type;
            switch (ResourcesHelper.IdentifyResourceType(ref resource))
            {
                case ResourceType.AnyHash:
                    type = "files";
                    break;
                case ResourceType.IP:
                    type = "ip_addresses";
                    break;
                case ResourceType.URL:
                    type = "urls";
                    break;
                case ResourceType.Domain:
                    type = "domains";
                    break;
                default:
                    throw new InvalidResourceException(
                        $"Resource {resource} must be any of a valid Hash,IP,Url or Domain");
            }

            if (string.IsNullOrWhiteSpace(comment))
                throw new ArgumentException("Comment must not be null or whitespace", nameof(comment));

            if (RestrictSizeLimits && comment.Length > CommentSizeRestriction)
                throw new ArgumentOutOfRangeException(nameof(comment), $"Your comment is larger than the maximum size of {CommentSizeRestriction / 1024} KB");

            var commentJson = JsonConvert.SerializeObject(new DataObject<TextAttribute>()
            {
                Type = "comment",
                Attributes = new TextAttribute() { Text = comment }
            });
            MultipartContent multi = new MultipartContent();
            multi.Add(CreateAcceptJsonPart());
            multi.Add(CreateApiPart());
            multi.Add(new StringContent(commentJson, Encoding.UTF8, "application/json"));

            //https://www.virustotal.com/api/v3/files/{id}/comments
            return GetResponse<CreateCommentResult>($"{type}/{resource}/comments/", HttpMethod.Post, multi);
        }
    }
}