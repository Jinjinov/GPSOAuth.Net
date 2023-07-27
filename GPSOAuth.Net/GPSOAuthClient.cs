using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace GPSOAuth.Net
{
    public class GPSOAuthClient : IGPSOAuthClient
    {
        private const string UserAgent = "GoogleAuth/1.4";
        private const string AuthUrl = "https://android.clients.google.com/auth";
        private const string B64Key = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" +
            "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" +
            "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" +
            "6rmf5AAAAAwEAAQ==";

        private readonly RSAParameters _androidKey = KeyFromB64(B64Key);

        private static async Task<Dictionary<string, string>> PerformAuthRequest(Dictionary<string, string> data)
        {
            using HttpClient client = new HttpClient();

            client.DefaultRequestHeaders.UserAgent.TryParseAdd(UserAgent);
            client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");

            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            HttpResponseMessage response = await client.PostAsync(AuthUrl, content);
            string responseContent = await response.Content.ReadAsStringAsync();

            return ParseAuthResponse(responseContent);
        }

        private static async Task<Dictionary<string, string>> PerformAuthRequestAsync(Dictionary<string, string> data)
        {
            HttpClientHandler handler = new HttpClientHandler
            {
                // default: DecompressionMethods.GZip | DecompressionMethods.Deflate
                AutomaticDecompression = DecompressionMethods.GZip,
                // default: true
                AllowAutoRedirect = false
            };

            using HttpClient tempHttpClient = new HttpClient(handler);

            tempHttpClient.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
            tempHttpClient.DefaultRequestHeaders.Add("Content-Type", "application/x-www-form-urlencoded");

            //HttpResponseMessage response;
            //using (FormUrlEncodedContent formUrlEncodedContent = new FormUrlEncodedContent(data))
            //{
            //    // When a request completes, dispose the request content so the user doesn't have to. This also
            //    // helps ensure that a HttpContent object is only sent once using HttpClient (similar to HttpRequestMessages
            //    // that can also be sent only once).
            //    response = await tempHttpClient.PostAsync(AuthUrl, formUrlEncodedContent).ConfigureAwait(false);
            //}

            FormUrlEncodedContent formUrlEncodedContent = new FormUrlEncodedContent(data);
            // When a request completes, dispose the request content so the user doesn't have to. This also
            // helps ensure that a HttpContent object is only sent once using HttpClient (similar to HttpRequestMessages
            // that can also be sent only once).
            HttpResponseMessage response = await tempHttpClient.PostAsync(AuthUrl, formUrlEncodedContent).ConfigureAwait(false);

            string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return ParseAuthResponse(content);
        }

        private static Dictionary<string, string> GenerateBaseRequest(
            string email,
            string encryptedPassword,
            string androidId,
            string service,
            string deviceCountry,
            string operatorCountry,
            string lang,
            int sdkVersion)
        {
            return new Dictionary<string, string>
            {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", email },
                { "has_permission", "1" },
                { "EncryptedPasswd",  encryptedPassword},
                { "service", service },
                { "source", "android" },
                { "androidId", androidId },
                { "device_country", deviceCountry },
                { "operatorCountry", operatorCountry },
                { "lang", lang },
                { "sdk_version", sdkVersion.ToString() }
            };
        }

        public Task<Dictionary<string, string>> PerformMasterLogin(
            string email,
            string password,
            string androidId,
            string service = "ac2dm",
            string clientSig = "38918a453d07199354f8b19af05ec6562ced5788",
            string deviceCountry = "us",
            string operatorCountry = "us",
            string lang = "en",
            int sdkVersion = 21)
        {
            string signature = CreateSignature(email, password, _androidKey);

            Dictionary<string, string> request = GenerateBaseRequest(email, signature, androidId, service, deviceCountry, operatorCountry, lang, sdkVersion);
            request.Add("add_account", "1");

            request.Add("client_sig", clientSig);
            request.Add("callerSig", clientSig);
            request.Add("droidguard_results", "dummy123");

            return PerformAuthRequest(request);
        }

        public Task<Dictionary<string, string>> PerformOAuth(
            string email,
            string masterToken,
            string androidId,
            string service,
            string app,
            string clientSig = "38918a453d07199354f8b19af05ec6562ced5788",
            string deviceCountry = "us",
            string operatorCountry = "us",
            string lang = "en",
            int sdkVersion = 21)
        {
            Dictionary<string, string> request = GenerateBaseRequest(email, masterToken, androidId, service, deviceCountry, operatorCountry, lang, sdkVersion);
            request.Add("app", app);
            request.Add("client_sig", clientSig);

            return PerformAuthRequest(request);
        }

        // BitConverter has different endianness, hence the Reverse()
        private static RSAParameters KeyFromB64(string b64Key)
        {
            byte[] decoded = Convert.FromBase64String(b64Key);

            int modLength = BitConverter.ToInt32(decoded.Take(4).Reverse().ToArray(), 0);
            byte[] mod = decoded.Skip(4).Take(modLength).ToArray();

            int expLength = BitConverter.ToInt32(decoded.Skip(modLength + 4).Take(4).Reverse().ToArray(), 0);
            byte[] exponent = decoded.Skip(modLength + 8).Take(expLength).ToArray();

            RSAParameters rsaKeyInfo = new RSAParameters
            {
                Modulus = mod,
                Exponent = exponent
            };

            return rsaKeyInfo;
        }

        // Python version returns a string, but we use byte[] to get the same results
        private static byte[] KeyToStruct(RSAParameters key)
        {
            byte[] modLength = { 0x00, 0x00, 0x00, 0x80 };
            byte[] mod = key.Modulus;

            byte[] expLength = { 0x00, 0x00, 0x00, 0x03 };
            byte[] exponent = key.Exponent;

            return CombineBytes(modLength, mod, expLength, exponent);
        }

        private static Dictionary<string, string> ParseAuthResponse(string text)
        {
            return text.Split(new[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split('='))
                .ToDictionary(parts => parts[0], parts => parts[1]);
        }

        private static string CreateSignature(string email, string password, RSAParameters key)
        {
            using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            rsa.ImportParameters(key);

            SHA1 sha1 = SHA1.Create();

            byte[] prefix = { 0x00 };
            byte[] hash = sha1.ComputeHash(KeyToStruct(key)).Take(4).ToArray();
            byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(email + "\x00" + password), true);

            return UrlSafeBase64(CombineBytes(prefix, hash, encrypted));
        }

        private static string UrlSafeBase64(byte[] byteArray)
        {
            return Convert.ToBase64String(byteArray).Replace('+', '-').Replace('/', '_');
        }

        private static byte[] CombineBytes(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }

            return rv;
        }
    }
}
