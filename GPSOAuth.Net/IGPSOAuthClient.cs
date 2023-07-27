using System.Collections.Generic;
using System.Threading.Tasks;

namespace GPSOAuth.Net
{
    public interface IGPSOAuthClient
    {
        Task<Dictionary<string, string>> PerformMasterLogin(
            string service = "ac2dm",
            string deviceCountry = "us",
            string operatorCountry = "us",
            string lang = "en",
            int sdkVersion = 21);

        Task<Dictionary<string, string>> PerformOAuth(
            string masterToken,
            string service,
            string app,
            string clientSig,
            string deviceCountry = "us",
            string operatorCountry = "us",
            string lang = "en",
            int sdkVersion = 21);
    }
}