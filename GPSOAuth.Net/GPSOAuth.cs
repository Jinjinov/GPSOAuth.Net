using System.Collections.Generic;

namespace GPSOAuth.Net
{
    public class OAuth
    {
        public Dictionary<string, string> PerformMasterLogin(string email, string password, string deviceId)
        {
            return new Dictionary<string, string>();
        }

        public Dictionary<string, string> PerformOAuth(
            string email,
            string masterToken,
            string deviceId,
            string[] service,
            string app,
            string client_sig)
        {
            return new Dictionary<string, string>();
        }
    }
}
