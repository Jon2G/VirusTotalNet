using Newtonsoft.Json;
using System;
using VirusTotalNet.Interfaces;

namespace VirusTotalNet
{
    public static class VirusTotal
    {
        private static Lazy<IVirusTotalAPI> _VirusTotalAPIV2;
        private static Lazy<IVirusTotalAPI> _VirusTotalAPIV3;
        public static IVirusTotalAPI V2 => _VirusTotalAPIV2?.Value;
        public static IVirusTotalAPI V3 => _VirusTotalAPIV3?.Value;
        public static void Configure(string apiKey, JsonSerializerSettings settings = null)
        {
            _VirusTotalAPIV2 = new Lazy<IVirusTotalAPI>(() => new VirusTotalNet.v2.VirusTotal(apiKey, settings));
            _VirusTotalAPIV3 = new Lazy<IVirusTotalAPI>(() => new VirusTotalNet.v3.VirusTotal(apiKey, settings));
        }
    }
}