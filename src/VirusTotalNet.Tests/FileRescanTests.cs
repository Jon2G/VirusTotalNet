using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests
{
    public class FileRescanTests : TestBase
    {
        [Fact]
        public async Task RescanKnownFile()
        {
            RescanResult fileResult = await VirusTotal.RescanFileAsync(TestData.EICARMalware);
            if (fileResult is VirusTotalNet.Results.v2.RescanResult rescanResultV2)
            {
                //It should always be in the VirusTotal database. We expect it to rescan it
                Assert.Equal(RescanResponseCode.Queued, rescanResultV2.ResponseCode);
            }
            else
            {
                Assert.NotNull(fileResult);
            }
        }

        //[Fact]
        //public async Task RescanInvalidFile()
        //{
        //    //TODO: Can't seem to provoke an error response code.
        //}

        [Fact]
        public async Task RescanMultipleKnownFile()
        {
            IEnumerable<RescanResult> fileResult = await VirusTotal.RescanFilesAsync(TestData.KnownHashes);

            foreach (RescanResult rescanResult in fileResult)
            {
                if (rescanResult is VirusTotalNet.Results.v2.RescanResult rescanResultV2)
                {
                    //It should always be in the VirusTotal database. We expect it to rescan it
                    Assert.Equal(RescanResponseCode.Queued, rescanResultV2.ResponseCode);
                }
                else
                {
                    Assert.NotNull(fileResult);
                }
            }
        }

        [Fact]
        public async Task RescanUnknownFile()
        {
            IgnoreMissingJson(" / Permalink", " / scan_id", " / SHA256");

            if (VirusTotal is VirusTotalNet.v2.VirusTotal)
            {
                VirusTotalNet.Results.v2.RescanResult fileResult = (VirusTotalNet.Results.v2.RescanResult)await VirusTotal.RescanFileAsync(TestData.GetRandomSHA1s(1).First());
                //It should not be in the VirusTotal database already, which means it should return error.
                Assert.Equal(RescanResponseCode.ResourceNotFound, fileResult.ResponseCode);
            }
            else
            {
                await Assert.ThrowsAsync<ResourceNotFoundException>(async () => await
                     VirusTotal.RescanFileAsync(TestData.GetRandomSHA1s(1).First()));
            }
        }

        [Fact]
        public async Task RescanSmallFile()
        {
            RescanResult fileResult = await VirusTotal.RescanFileAsync(new byte[1]);
            if (fileResult is VirusTotalNet.Results.v2.RescanResult rescanResultV2)
            {
                //It should not be in the VirusTotal database already, which means it should return error.
                Assert.Equal(RescanResponseCode.Queued, rescanResultV2.ResponseCode);
            }
            else
            {
                Assert.NotNull(fileResult);
            }
        }

        [Fact]
        public async Task RescanBatchLimit()
        {
            IgnoreMissingJson("[array] / Permalink", "[array] / scan_id", "[array] / SHA256");

            VirusTotal.RestrictNumberOfResources = false;
            if (VirusTotal is VirusTotalNet.v2.VirusTotal)
            {
                IEnumerable<RescanResult> results = await VirusTotal.RescanFilesAsync(TestData.GetRandomSHA1s(50));
                //We only expect 25 as VT simply returns 25 results no matter the batch size.
                Assert.Equal(VirusTotal.RescanBatchSizeLimit, results.Count());
            }
            else
            {
                await Assert.ThrowsAsync<ResourceNotFoundException>(async () => await VirusTotal.RescanFilesAsync(TestData.GetRandomSHA1s(50)));
            }
        }
    }
}