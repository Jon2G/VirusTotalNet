using Newtonsoft.Json;

namespace VirusTotalNet.Internal.Objects.v3
{
    public class LastAnalysisResults
    {
        [JsonProperty("CMC Threat Intelligence")]
        public LastAnalysisStats CMCThreatIntelligence { get; set; }
        [JsonProperty("Snort IP sample list")]
        public LastAnalysisStats SnortIPSampleList { get; set; }
        [JsonProperty("0xSI_f33d")]
        public LastAnalysisStats _0xSI_f33d { get; set; }
        [JsonProperty("Armis")]
        public LastAnalysisStats Armis { get; set; }
        [JsonProperty("ViriBack")]
        public LastAnalysisStats ViriBack { get; set; }
        [JsonProperty("Comodo Valkyrie Verdict")]
        public LastAnalysisStats ComodoValkyrieVerdict { get; set; }
        [JsonProperty("PhishLabs")]
        public LastAnalysisStats PhishLabs { get; set; }
        [JsonProperty("K7AntiVirus")]
        public LastAnalysisStats K7AntiVirus { get; set; }
        [JsonProperty("CINS Army")]
        public LastAnalysisStats CINSArmy { get; set; }
        [JsonProperty("Quttera")]
        public LastAnalysisStats Quttera { get; set; }
        [JsonProperty("OpenPhish")]
        public LastAnalysisStats OpenPhish { get; set; }
        [JsonProperty("VX Vault")]
        public LastAnalysisStats VXVault { get; set; }
        [JsonProperty("Web Security Guard")]
        public LastAnalysisStats WebSecurityGuard { get; set; }
        [JsonProperty("Scantitan")]
        public LastAnalysisStats Scantitan { get; set; }
        [JsonProperty("AlienVault")]
        public LastAnalysisStats AlienVault { get; set; }
        [JsonProperty("Sophos")]
        public LastAnalysisStats Sophos { get; set; }
        [JsonProperty("Phishtank")]
        public LastAnalysisStats Phishtank { get; set; }
        [JsonProperty("EonScope")]
        public LastAnalysisStats EonScope { get; set; }
        [JsonProperty("CyberCrime")]
        public LastAnalysisStats CyberCrime { get; set; }
        [JsonProperty("Spam404")]
        public LastAnalysisStats Spam404 { get; set; }
        [JsonProperty("SecureBrain")]
        public LastAnalysisStats SecureBrain { get; set; }
        [JsonProperty("Hoplite Industries")]
        public LastAnalysisStats HopliteIndustries { get; set; }
        [JsonProperty("AutoShun")]
        public LastAnalysisStats AutoShun { get; set; }
        [JsonProperty("Fortinet")]
        public LastAnalysisStats Fortinet { get; set; }
        [JsonProperty("alphaMountain.ai")]
        public LastAnalysisStats AlphaMountainAi { get; set; }
        [JsonProperty("Lionic")]
        public LastAnalysisStats Lionic { get; set; }
        [JsonProperty("Virusdie External Site Scan")]
        public LastAnalysisStats VirusdieExternalSiteScan { get; set; }
        [JsonProperty("Google Safebrowsing")]
        public LastAnalysisStats GoogleSafebrowsing { get; set; }
        [JsonProperty("SafeToOpen")]
        public LastAnalysisStats SafeToOpen { get; set; }
        [JsonProperty("ADMINUSLabs")]
        public LastAnalysisStats ADMINUSLabs { get; set; }
        [JsonProperty("Cyan")]
        public LastAnalysisStats Cyan { get; set; }
        [JsonProperty("Heimdal Security")]
        public LastAnalysisStats HeimdalSecurity { get; set; }
        [JsonProperty("CRDF")]
        public LastAnalysisStats CRDF { get; set; }
        [JsonProperty("Trustwave")]
        public LastAnalysisStats Trustwave { get; set; }
        [JsonProperty("AICC (MONITORAPP)")]
        public LastAnalysisStats AICC { get; set; }
        [JsonProperty("CyRadar")]
        public LastAnalysisStats CyRadar { get; set; }
        [JsonProperty("Dr.Web")]
        public LastAnalysisStats DrWeb { get; set; }
        [JsonProperty("Emsisoft")]
        public LastAnalysisStats Emsisoft { get; set; }
        [JsonProperty("Abusix")]
        public LastAnalysisStats Abusix { get; set; }
        [JsonProperty("Webroot")]
        public LastAnalysisStats Webroot { get; set; }
        [JsonProperty("Avira")]
        public LastAnalysisStats Avira { get; set; }
        [JsonProperty("securolytics")]
        public LastAnalysisStats Securolytics { get; set; }
        [JsonProperty("Antiy-AVL")]
        public LastAnalysisStats Antiy_AVL { get; set; }
        [JsonProperty("Acronis")]
        public LastAnalysisStats Acronis { get; set; }
        [JsonProperty("Quick Heal")]
        public LastAnalysisStats QuickHeal { get; set; }
        [JsonProperty("ESTsecurity-Threat Inside")]
        public LastAnalysisStats ESTsecurityThreatInside { get; set; }
        [JsonProperty("DNS8")]
        public LastAnalysisStats DNS8 { get; set; }
        [JsonProperty("benkow.cc")]
        public LastAnalysisStats Benkow_cc { get; set; }
        [JsonProperty("EmergingThreats")]
        public LastAnalysisStats EmergingThreats { get; set; }
        [JsonProperty("Chong Lua Dao")]
        public LastAnalysisStats ChongLuaDao { get; set; }
        [JsonProperty("Yandex Safebrowsing")]
        public LastAnalysisStats YandexSafebrowsing { get; set; }
        [JsonProperty("MalwareDomainList")]
        public LastAnalysisStats MalwareDomainList { get; set; }
        [JsonProperty("Lumu")]
        public LastAnalysisStats Lumu { get; set; }
        [JsonProperty("zvelo")]
        public LastAnalysisStats Zvelo { get; set; }
        [JsonProperty("Kaspersky")]
        public LastAnalysisStats Kaspersky { get; set; }
        [JsonProperty("Segasec")]
        public LastAnalysisStats Segasec { get; set; }
        [JsonProperty("Sucuri SiteCheck")]
        public LastAnalysisStats SucuriSiteCheck { get; set; }
        [JsonProperty("desenmascara.me")]
        public LastAnalysisStats Desenmascara_me { get; set; }
        [JsonProperty("URLhaus")]
        public LastAnalysisStats URLhaus { get; set; }
        [JsonProperty("PREBYTES")]
        public LastAnalysisStats PREBYTES { get; set; }
        [JsonProperty("StopForumSpam")]
        public LastAnalysisStats StopForumSpam { get; set; }
        [JsonProperty("Blueliv")]
        public LastAnalysisStats Blueliv { get; set; }
        [JsonProperty("Netcraft")]
        public LastAnalysisStats Netcraft { get; set; }
        [JsonProperty("ZeroCERT")]
        public LastAnalysisStats ZeroCERT { get; set; }
        [JsonProperty("Phishing Database")]
        public LastAnalysisStats PhishingDatabase { get; set; }
        [JsonProperty("MalwarePatrol")]
        public LastAnalysisStats MalwarePatrol { get; set; }
        [JsonProperty("MalBeacon")]
        public LastAnalysisStats MalBeacon { get; set; }
        [JsonProperty("IPsum")]
        public LastAnalysisStats IPsum { get; set; }
        [JsonProperty("Spamhaus")]
        public LastAnalysisStats Spamhaus { get; set; }
        [JsonProperty("Malwared")]
        public LastAnalysisStats Malwared { get; set; }
        [JsonProperty("BitDefender")]
        public LastAnalysisStats BitDefender { get; set; }
        [JsonProperty("GreenSnow")]
        public LastAnalysisStats GreenSnow { get; set; }
        [JsonProperty("G-Data")]
        public LastAnalysisStats G_Data { get; set; }
        [JsonProperty("StopBadware")]
        public LastAnalysisStats StopBadware { get; set; }
        [JsonProperty("SCUMWARE.org")]
        public LastAnalysisStats SCUMWARE_org { get; set; }
        [JsonProperty("malwares.com URL checker")]
        public LastAnalysisStats Malwares_comURLChecker { get; set; }
        [JsonProperty("NotMining")]
        public LastAnalysisStats NotMining { get; set; }
        [JsonProperty("Forcepoint ThreatSeeker")]
        public LastAnalysisStats ForcepointThreatSeeker { get; set; }
        [JsonProperty("Certego")]
        public LastAnalysisStats Certego { get; set; }
        [JsonProperty("ESET")]
        public LastAnalysisStats ESET { get; set; }
        [JsonProperty("Threatsourcing")]
        public LastAnalysisStats Threatsourcing { get; set; }
        [JsonProperty("MalSilo")]
        public LastAnalysisStats MalSilo { get; set; }
        [JsonProperty("Nucleon")]
        public LastAnalysisStats Nucleon { get; set; }
        [JsonProperty("BADWARE.INFO")]
        public LastAnalysisStats BADWARE_INFO { get; set; }
        [JsonProperty("ThreatHive")]
        public LastAnalysisStats ThreatHive { get; set; }
        [JsonProperty("FraudScore")]
        public LastAnalysisStats FraudScore { get; set; }
        [JsonProperty("Tencent")]
        public LastAnalysisStats Tencent { get; set; }
        [JsonProperty("Bfore.Ai PreCrime")]
        public LastAnalysisStats Bfore_AiPreCrime { get; set; }
        [JsonProperty("Baidu-International")]
        public LastAnalysisStats Baidu_International { get; set; }
    }
}
