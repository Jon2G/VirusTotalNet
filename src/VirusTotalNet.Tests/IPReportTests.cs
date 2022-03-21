using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests
{
    public class IPReportTests : TestBase
    {
        [Fact]
        public async Task GetIPReportKnownIPv4()
        {
            IgnoreMissingJson("detected_referrer_samples[array] / Date");

            IPReport report = await VirusTotal.GetIPReportAsync(TestData.KnownIPv4s.First());
            if (report is VirusTotalNet.Results.v2.IPReport ipReportv2)
                Assert.Equal(IPReportResponseCode.Present, ipReportv2.ResponseCode);
            else
                Assert.NotNull(report);
        }

        [Fact]
        public async Task GetIPReportUnknownIPv4()
        {
            //Unknown hosts do not have all this in the response
            IgnoreMissingJson(" / undetected_urls", " / as_owner", " / ASN", " / Country", " / detected_communicating_samples", " / detected_downloaded_samples", " / detected_referrer_samples", " / detected_urls", " / Resolutions", " / undetected_communicating_samples", " / undetected_downloaded_samples", " / undetected_referrer_samples");

            IPReport report = await VirusTotal.GetIPReportAsync("128.168.238.15");
            if (report is VirusTotalNet.Results.v2.IPReport ipReportv2)
                Assert.Equal(IPReportResponseCode.NotPresent, ipReportv2.ResponseCode);
            else
                Assert.NotNull(report);
        }

        [Fact]
        public async Task GetIPReportRandomIPv6()
        {
            //IPv6 is not supported
            await Assert.ThrowsAsync<InvalidResourceException>(async () => await VirusTotal.GetIPReportAsync(TestData.GetRandomIPv6s(1).First()));
        }
    }
}