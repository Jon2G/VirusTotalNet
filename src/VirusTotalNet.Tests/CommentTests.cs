﻿using System;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Helpers;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.Tests
{
    public class CommentTests : TestBase
    {
        [Fact]
        public async Task CreateValidComment()
        {
            CreateCommentResult comment = await VirusTotal.CreateCommentAsync(TestData.TestHash, "VirusTotal.NET test - " + DateTime.UtcNow.ToString("O"));
            if (comment is VirusTotalNet.Results.v2.CreateCommentResult commentResultV2)
            {
                Assert.Equal(CommentResponseCode.Success, commentResultV2.ResponseCode);
                Assert.Equal("Your comment was successfully posted", commentResultV2.VerboseMsg);
            }
            else
            {
                Assert.NotNull(comment);
            }
        }

        [Fact]
        public async Task CreateCommentOnUnknownResource()
        {
            CreateCommentResult comment = await VirusTotal.CreateCommentAsync(TestData.GetRandomSHA1s(1).First(), "VirusTotal.NET test - " + DateTime.UtcNow.ToString("O"));
            if (comment is VirusTotalNet.Results.v2.CreateCommentResult commentResultV2)
            {
                Assert.Equal(CommentResponseCode.Error, commentResultV2.ResponseCode);
                Assert.Equal("Could not find resource", commentResultV2.VerboseMsg);
            }
            else
            {
                Assert.Null(comment);
            }
        }

        [Fact]
        public async Task CreateDuplicateComment()
        {
            //Create the comment. This might fail with an error, but it does not matter.
            try
            {
                await VirusTotal.CreateCommentAsync(TestData.TestHash, "VirusTotal.NET test");
            }
            catch (Exception) { }

            if (VirusTotal is VirusTotalNet.v2.VirusTotal)
            {
                VirusTotalNet.Results.v2.CreateCommentResult comment =
                    (VirusTotalNet.Results.v2.CreateCommentResult)await VirusTotal.CreateCommentAsync(TestData.TestHash,
                        "VirusTotal.NET test");
                Assert.Equal(CommentResponseCode.Error, comment.ResponseCode);
                Assert.Equal("Duplicate comment", comment.VerboseMsg);
            }
            else
            {
                await Assert.ThrowsAsync<ResourceConflictException>(async () => await VirusTotal.CreateCommentAsync(
                     TestData.TestHash,
                     "VirusTotal.NET test"));
            }
        }

        [Fact]
        public async Task CreateLargeComment()
        {
            byte[] content = new byte[1024 * 4];
            string contentInHex = HashHelper.ByteArrayToHex(content); //2x size now

            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await VirusTotal.CreateCommentAsync(TestData.TestHash, contentInHex));
        }

        [Fact]
        public async Task CreateEmptyComment()
        {
            await Assert.ThrowsAsync<ArgumentException>(async () => await VirusTotal.CreateCommentAsync(TestData.TestHash, string.Empty));
        }

        //[Fact]
        //public async Task GetComment()
        //{
        //    CommentResult comment = await VirusTotal.GetCommentAsync(TestData.TestHash);
        //}

        //[Fact]
        //public async Task GetCommentOnUnknownResource()
        //{
        //    CommentResult comment = await VirusTotal.GetCommentAsync(TestData.GetRandomSHA1s(1).First());
        //}

        //[Fact]
        //public async Task GetCommentWithBefore()
        //{
        //    CommentResult comment = await VirusTotal.GetCommentAsync(TestData.TestHash, DateTime.UtcNow); //TODO: before
        //}
    }
}