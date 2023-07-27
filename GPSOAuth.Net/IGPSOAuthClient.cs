using System.Collections.Generic;
using System.Threading.Tasks;

namespace GPSOAuth.Net
{
    public interface IGPSOAuthClient
    {
        Task<Dictionary<string, string>> PerformMasterLogin(
            string email,
            string password,
            string androidId,
            string service = "ac2dm",
            string clientSig = "38918a453d07199354f8b19af05ec6562ced5788",
            string deviceCountry = "us",
            string operatorCountry = "us",
            string lang = "en",
            int sdkVersion = 21);

        Task<Dictionary<string, string>> PerformOAuth(
            string email,
            string masterToken,
            string androidId,
            string service,
            string app,
            string clientSig = "38918a453d07199354f8b19af05ec6562ced5788",
            string deviceCountry = "us",
            string operatorCountry = "us",
            string lang = "en",
            int sdkVersion = 21);
    }
}