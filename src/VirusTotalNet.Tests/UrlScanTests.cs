using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests
{
    public class UrlScanTests : TestBase
    {
        [Fact]
        public async Task ScanKnownUrl()
        {
            VirusTotalNet.Results.UrlScanResult fileResult = await VirusTotal.ScanUrlAsync(TestData.KnownUrls.First());
            if (fileResult is VirusTotalNet.Results.v2.UrlScanResult urlScanResultv2)
                Assert.Equal(UrlScanResponseCode.Queued, urlScanResultv2.ResponseCode);
            else
                Assert.NotNull(fileResult);
        }

        [Fact]
        public async Task ScanMultipleKnownUrls()
        {
            IEnumerable<UrlScanResult> urlScans = await VirusTotal.ScanUrlsAsync(TestData.KnownUrls);

            foreach (UrlScanResult urlScan in urlScans)
            {
                if (urlScan is VirusTotalNet.Results.v2.UrlScanResult urlScanResultv2)
                    Assert.Equal(UrlScanResponseCode.Queued, urlScanResultv2.ResponseCode);
                else
                    Assert.NotNull(urlScan);
            }
        }

        [Fact]
        public async Task ScanUnknownUrl()
        {
            UrlScanResult fileResult = await VirusTotal.ScanUrlAsync(TestData.GetUnknownUrls(1).First());
            if (fileResult is VirusTotalNet.Results.v2.UrlScanResult urlScanResultv2)
                Assert.Equal(UrlScanResponseCode.Queued, urlScanResultv2.ResponseCode);
            else
                Assert.NotNull(fileResult);
        }

        [Fact]
        public async Task ScanMultipleUnknownUrl()
        {
            IEnumerable<UrlScanResult> urlScans = await VirusTotal.ScanUrlsAsync(TestData.GetUnknownUrls(5));

            foreach (UrlScanResult urlScan in urlScans)
            {
                if (urlScan is VirusTotalNet.Results.v2.UrlScanResult urlScanResultv2)
                    Assert.Equal(UrlScanResponseCode.Queued, urlScanResultv2.ResponseCode);
                else
                    Assert.NotNull(urlScan);
            }
        }

        [Fact]
        public async Task UrlScanBatchLimit()
        {
            VirusTotal.RestrictNumberOfResources = false;

            IEnumerable<UrlScanResult> results = await VirusTotal.ScanUrlsAsync(TestData.GetUnknownUrls(50));
            if (VirusTotal is VirusTotalNet.v2.VirusTotal)
            {
                //We only expect 25 as VT simply returns 25 results no matter the batch size.
                Assert.Equal(VirusTotal.UrlScanBatchSizeLimit, results.Count());
            }
            else
            {
                Assert.Equal(50, results.Count());
            }
        }
    }
}