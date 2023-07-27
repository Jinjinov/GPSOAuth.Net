using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading.Tasks;

namespace GPSOAuth.Net.Test;

public class Program
{
    static readonly JsonSerializerOptions _jsonSerializerOptions = new() { WriteIndented = true };

    public static async Task Main(string[] _)
    {
        Console.WriteLine("Google account email: ");
        string email = Console.ReadLine();

        Console.WriteLine("Password: ");
        string password = Console.ReadLine();

        await Run(email, password);

        Console.ReadKey();
    }

    public static async Task Run(string email, string password)
    {
        string deviceId = NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(nic => nic.GetPhysicalAddress().ToString())
                .FirstOrDefault();

        GPSOAuthClient client = new();

        Dictionary<string, string> master = await client.PerformMasterLogin(email, password, deviceId);

        Console.WriteLine("Master Login:");
        Console.WriteLine(JsonSerializer.Serialize(master, _jsonSerializerOptions));

        if (master.TryGetValue("Token", out string token))
        {
            Dictionary<string, string> oath = await client.PerformOAuth(email, token, deviceId, "sj", "com.google.android.music");

            Console.WriteLine("OAuth Login:");
            Console.WriteLine(JsonSerializer.Serialize(oath, _jsonSerializerOptions));
        }
        else
        {
            Console.WriteLine("MasterLogin failed (check credentials)");
        }

        Console.ReadKey();
    }
}

