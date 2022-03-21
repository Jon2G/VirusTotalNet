using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests
{
    public class DomainReportTests : TestBase
    {
        [Fact]
        public async Task GetDomainReportKnownDomain()
        {
            var report = await VirusTotal.GetDomainReportAsync(TestData.KnownDomains.First());
            if (report is VirusTotalNet.Results.v2.DomainReport v2Report)
                Assert.Equal(DomainResponseCode.Present, v2Report.ResponseCode);
            Assert.NotNull(report);

        }

        //[Fact]
        //public async Task GetDomainReportInvalidDomain()
        //{
        //    //TODO: I can't find a domain that VT does not think is valid.
        //    //Domains tried:
        //    //-
        //    //.
        //    //%20
        //    //%2F
        //}

        [Fact]
        public async Task GetDomainReportUnknownDomain()
        {
            //Reports don't contain all these fields when it is unknown
            IgnoreMissingJson(" / undetected_urls", " / Alexa category", " / Alexa domain info", " / Alexa rank", " / BitDefender category", " / BitDefender domain info", " / Categories", " / detected_communicating_samples", " / detected_downloaded_samples", " / detected_referrer_samples", " / detected_urls", " / domain_siblings", " / Dr.Web category", " / Forcepoint ThreatSeeker category", " / Opera domain info", " / Pcaps", " / Resolutions", " / subdomains", " / TrendMicro category", " / undetected_communicating_samples", " / undetected_downloaded_samples", " / undetected_referrer_samples", " / Websense ThreatSeeker category", " / Webutation domain info", " / whois", " / whois_timestamp", " / WOT domain info");

            DomainReport report = await VirusTotal.GetDomainReportAsync(TestData.GetUnknownDomains(1).First());
            if (report is VirusTotalNet.Results.v2.DomainReport v2Report)
                Assert.Equal(DomainResponseCode.NotPresent, v2Report.ResponseCode);
            Assert.NotNull(report);
        }
    }
}