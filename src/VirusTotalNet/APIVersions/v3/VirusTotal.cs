using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.APIVersions;
using VirusTotalNet.Enums;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;
using VirusTotalNet.Internal.Attributes;
using VirusTotalNet.Internal.Objects.v3;
using VirusTotalNet.Internal.Other;
using VirusTotalNet.Results;
using FileReport = VirusTotalNet.Results.FileReport;

// ReSharper disable once CheckNamespace
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

        protected override async Task<T> GetResponse<T>(string url,
            HttpMethod method, HttpContent content, Dictionary<string, string> Headers = null) where T : class
        {
            HttpResponseMessage response = await SendRequest(url, method, content, Headers).ConfigureAwait(false);
            if (response is null)
            {
                return null;
            }
            using (Stream responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (StreamReader sr = new StreamReader(responseStream, Encoding.UTF8))
            using (JsonTextReader jsonTextReader = new JsonTextReader(sr))
            {
                jsonTextReader.CloseInput = false;

                SaveResponse(responseStream);
                T result;
                var type = typeof(T);

                if (type == typeof(DataWrapper) ||
                    type.IsGenericType && (
                        type.GetGenericTypeDefinition() == typeof(SimpleDataWrapper<>) ||
                        type.GetGenericTypeDefinition() == typeof(DataWrapper<>) ||
                        type.GetGenericTypeDefinition() == typeof(DataObject<>)))
                {
                    var resultDataObject = _serializer.Deserialize<T>(jsonTextReader);
                    result = resultDataObject as T;
                }
                else
                {
                    var resultDataObject = _serializer.Deserialize<DataWrapper<T>>(jsonTextReader);
                    result = resultDataObject?.Data is null ? default(T) : resultDataObject.Data.Attributes;
                }
                return result;
            }
        }


        protected Dictionary<string, string> CreateHeaders()
        {
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                {"x-apikey",_defaultValues["apikey"]},
                {"Accept","application/json"}
            };
            return headers;
        }


        /// <summary>
        /// Scan a file.
        /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
        /// Note: You are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
        /// </summary>
        /// <param name="stream">The file to scan</param>
        /// <param name="filename">The filename of the file</param>
        public override async Task<ScanResult> ScanFileAsync(Stream stream, string filename)
        {
            ValidateScanFileArguments(stream, FileSizeLimit, filename);

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateApiPart());
            multi.Add(CreateFileContent(stream, filename));
            var headers = CreateHeaders();
            //https://www.virustotal.com/api/v3/files
            var result = await GetResponse<DataWrapper>("files", HttpMethod.Post, multi, headers);
            return new VirusTotalNet.Results.v3.ScanResult()
            {
                ScanId = result.Data.Id,
                Type = result.Data.Type
            };
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
            var Headers = CreateHeaders();

            var uploadUrlObj = await GetResponse<SimpleDataWrapper<string>>("files/upload_url", HttpMethod.Get, null, Headers);

            if (string.IsNullOrEmpty(uploadUrlObj.Data))
                throw new Exception("Something when wrong while getting the upload url. Are you using an API key with support for this request?");

            MultipartFormDataContent multi = new MultipartFormDataContent();
            multi.Add(CreateFileContent(stream, filename, false)); //The big file upload API does not like it when multi-part uploads contain the size field
            var response = await GetResponse<DataWrapper>(uploadUrlObj.Data, HttpMethod.Post, multi, Headers);
            return new Results.v3.ScanResult()
            {
                Type = response.Data.Type,
                ScanId = response.Data.Id
            };
        }

        /// <summary>
        /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
        /// Note: Before requesting a rescan you should retrieve the latest report on the file.
        /// </summary>
        /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
        public override async Task<RescanResult> RescanFileAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash);
            var Headers = CreateHeaders();
            //https://www.virustotal.com/api/v3/files/{id}/analyse
            var result = await GetResponse<SimpleDataWrapper<VirusTotalNet.Results.v3.RescanResult>>($"files/{resource}/analyse", HttpMethod.Post, null, Headers);
            return result.Data;
            //return new VirusTotalNet.Results.v3.RescanResult()
            //{
            //    Type = response.Data.Type,
            //    ScanId = response.Data.Id
            //};
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
        public override async Task<IEnumerable<RescanResult>> RescanFilesAsync(IEnumerable<string> resourceList)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            List<RescanResult> results = new List<RescanResult>();
            foreach (string resoruce in resourceList)
            {
                results.Add(await RescanFileAsync(resoruce));
            }
            return results;
        }

        /// <summary>
        /// Gets the report of the file.
        /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
        /// </summary>
        /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
        public override async Task<FileReport> GetFileReportAsync(string resource)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.ScanId);
            var Headers = CreateHeaders();
            //https://www.virustotal.com/api/v3/files/{id}
            return await GetResponse<VirusTotalNet.Results.v3.FileReport>($"files/{resource}", HttpMethod.Get, null, Headers);
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
        public override async Task<IEnumerable<FileReport>> GetFileReportsAsync(IEnumerable<string> resourceList)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            List<FileReport> results = new List<FileReport>();
            foreach (string resoruce in resourceList)
            {
                results.Add(await GetFileReportAsync(resoruce));
            }
            return results;
        }

        /// <summary>
        /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest report on the URL.
        /// </summary>
        /// <param name="url">The URL to process.</param>
        public override async Task<UrlScanResult> ScanUrlAsync(string url)
        {
            url = ResourcesHelper.ValidateResourcea(url, ResourceType.URL);
            //Required
            IDictionary<string, string> values = new Dictionary<string, string>
            {
                { "url", url }
            };
            //https://www.virustotal.com/api/v3/urls
            var data = await GetResponse<DataWrapper>("urls", HttpMethod.Post,
                CreateURLEncodedContent(values), CreateHeaders());
            return new Results.v3.UrlScanResult()
            {
                ScanId = data.Data.Id,
                Type = data.Data.Type
            };
        }

        protected override HttpContent CreateURLEncodedContent(IDictionary<string, string> values)
        {
            return new CustomURLEncodedContent(values);
        }

        /// <summary>
        /// Batch url scan is deprecated on API v3, this will send as many requests as the number of urls.
        /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
        /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
        /// </summary>
        /// <param name="urls">The URLs to process.</param>
        [Obsolete("Batch url scan is deprecated on API v3, this will send as many requests as the number of urls.")]
#pragma warning disable CS0809 // Obsolete member overrides non-obsolete member
        public override async Task<IEnumerable<UrlScanResult>> ScanUrlsAsync(IEnumerable<string> urls)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            List<UrlScanResult> results = new List<UrlScanResult>();
            foreach (string url in urls)
            {
                results.Add(await ScanUrlAsync(url));
            }
            return results;
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
            var Headers = CreateHeaders();
            var report = await GetResponse<VirusTotalNet.Results.v3.UrlReport>($"urls/{HashHelper.GetSha256(url)}", HttpMethod.Get, null, Headers);
            if (scanIfNoReport && report is null)
            {
                await ScanUrlAsync(url);
                report = (VirusTotalNet.Results.v3.UrlReport)await GetUrlReportAsync(url, false);
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
        public override async Task<IEnumerable<UrlReport>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false)
#pragma warning restore CS0809 // Obsolete member overrides non-obsolete member
        {
            List<UrlReport> results = new List<UrlReport>();
            foreach (string url in urls)
            {
                results.Add(await GetUrlReportAsync(url, scanIfNoReport));
            }
            return results;
        }

        /// <summary>
        /// Gets a scan report from an IP
        /// </summary>
        /// <param name="ip">The IP you wish to get the report on.</param>
        public override async Task<IPReport> GetIPReportAsync(string ip)
        {
            //https://www.virustotal.com/api/v3/ip_addresses/{ip}
            var Headers = CreateHeaders();
            ip = ResourcesHelper.ValidateResourcea(ip, ResourceType.IP);
            return (IPReport)await GetResponse<VirusTotalNet.Results.v3.IPReport>($"ip_addresses/{ip}", HttpMethod.Get, null, Headers);
        }

        /// <summary>
        /// Gets a scan report from a domain
        /// </summary>
        /// <param name="domain">The domain you wish to get the report on.</param>
        public override async Task<DomainReport> GetDomainReportAsync(string domain)
        {
            var Headers = CreateHeaders();
            domain = ResourcesHelper.ValidateResourcea(domain, ResourceType.Domain);
            //https://www.virustotal.com/api/v3/domains/{domain}
            return await GetResponse<VirusTotalNet.Results.v3.DomainReport>($"domains/{domain}", HttpMethod.Get, null, Headers);
        }

        /// <summary>
        /// Retrieves a comment on a resource.
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="before">TODO:Date has no effect!</param>
        public override Task<CommentResult> GetCommentAsync(string resource, DateTime? before = null)
        {
            resource = ResourcesHelper.ValidateResourcea(resource, ResourceType.AnyHash | ResourceType.IP | ResourceType.URL | ResourceType.Domain);
            var Headers = CreateHeaders();


            //TODO: before

            //https://www.virustotal.com/api/v3/comments
            return GetResponse<CommentResult>($"comments/{resource}", HttpMethod.Get, null, Headers);
        }

        /// <summary>
        /// Creates a comment on a resource
        /// </summary>
        /// <param name="resource">The MD5/SHA1/SHA256 hash or URL.</param>
        /// <param name="comment">The comment you wish to add.</param>
        public override async Task<CreateCommentResult> CreateCommentAsync(string resource, string comment)
        {
            string type;
            switch (ResourcesHelper.IdentifyResourceType(ref resource))
            {
                case ResourceType.MD5:
                case ResourceType.SHA1:
                case ResourceType.SHA256:
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

            var commentJson = JsonConvert.SerializeObject(new DataWrapper<TextAttribute>()
            {
                Data = new DataObject<TextAttribute>()
                {
                    Type = "comment",
                    Attributes = new VirusTotalNet.Internal.Attributes.TextAttribute() { Text = comment }
                }
            });
            var Headers = CreateHeaders();
            var content = new StringContent(commentJson, Encoding.UTF8, "application/json");

            //https://www.virustotal.com/api/v3/files/{id}/comments
            return await GetResponse<VirusTotalNet.Results.v3.CreateCommentResult>($"{type}/{resource}/comments", HttpMethod.Post, content, Headers);
        }
    }
}