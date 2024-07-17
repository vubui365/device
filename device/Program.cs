using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace SimpleSnmpScanner
{
    class Program
    {
        static async Task Main()
        {
            Console.WriteLine("Please enter IPv4 here:");
            string? ipAddress = Console.ReadLine();

            if (!IPAddress.TryParse(ipAddress, out IPAddress? address))
            {
                Console.WriteLine("Invalid IPv4 address.");
                return;
            }

            try
            {
                // 1. Kiểm tra trạng thái online/offline (giữ nguyên)
                bool isOnline = PingHost(address);
                Console.WriteLine($"Status: {(isOnline ? "Online" : "Offline")}");

                if (!isOnline) return;

                // 2. Lấy thông tin SNMP 
                var result = await GetSnmpData(address);

                if (result != null)
                {
                    Console.WriteLine("Device Name: " + result["1.3.6.1.2.1.1.5.0"]);
                    Console.WriteLine("MAC Address: " + result["1.3.6.1.2.1.2.2.1.6"]);
                }
                else
                {
                    Console.WriteLine("Failed to retrieve SNMP data.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        // Hàm PingHost (giữ nguyên)
        static bool PingHost(IPAddress address)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(address);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }

        // Hàm GetSnmpData (sửa đổi)
        static async Task<Dictionary<string, string>?> GetSnmpData(IPAddress address)
        {
            var result = new Dictionary<string, string>();
            var oids = new List<ObjectIdentifier> {
                new ObjectIdentifier(".1.3.6.1.2.1.1.5.0"),  // sysName
                new ObjectIdentifier(".1.3.6.1.2.1.2.2.1.6")   // ifPhysAddress (MAC)
            };

            // Chuyển đổi List<ObjectIdentifier> thành List<Variable>
            var variables = oids.ConvertAll(oid => new Variable(oid));
            var getResponse = await Messenger.GetAsync(VersionCode.V3, new IPEndPoint(address, 161), 
                new OctetString("public"), variables); 
            try
            {

                if (getResponse != null && getResponse.Count > 0) // Kiểm tra phản hồi
                {
                    foreach (var vb in getResponse)
                    {
                        result[vb.Id.ToString()] = vb.Data.ToString();
                    }
                }

                return result;
            }
            catch (Lextm.SharpSnmpLib.Messaging.TimeoutException ex)
            {
                Console.WriteLine($"Timeout Error: {ex.Message}");
                return null;
            }
            catch (SnmpException ex)
            {
                Console.WriteLine($"SNMP Error: {ex.Message}");
                return null;
            }
            
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return null;
            }
        }
    }
}
