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
        // Hằng số OID (để dễ đọc và bảo trì hơn)
        const string SysNameOid = ".1.3.6.1.2.1.1.5.0";
        const string IfPhysAddressOid = ".1.3.6.1.2.1.2.2.1.6";
        const string SysDescrOid = ".1.3.6.1.2.1.1.1.0";
        const string SysContactOid = ".1.3.6.1.2.1.1.4.0";
        const string SysLocationOid = ".1.3.6.1.2.1.1.6.0";
        const string IfNumberOid = ".1.3.6.1.2.1.2.1.0";
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
                // 1. Kiểm tra trạng thái online/offline
                bool isOnline = PingHost(address);
                Console.WriteLine($"Status: {(isOnline ? "Online" : "Offline")}");

                if (!isOnline) return;

                // 2. Lấy thông tin SNMP 
                var result = await GetSnmpData(address);

                if (result != null)
                {
                    Console.WriteLine("Device Name: " + result[SysNameOid]);
                    Console.WriteLine("MAC Address: " + result[IfPhysAddressOid]);
                    Console.WriteLine("Description: " + result[SysDescrOid]);
                    Console.WriteLine("Contact: " + result[SysContactOid]);
                    Console.WriteLine("Location: " + result[SysLocationOid]);
                    Console.WriteLine("Number of interfaces: " + result[IfNumberOid]);
                }
                else
                {
                    Console.WriteLine("Failed to retrieve SNMP data.");
                }
            }
            catch (Lextm.SharpSnmpLib.Messaging.TimeoutException ex)
            {
                Console.WriteLine($"Timeout Error: {ex.Message}");
                
            }
            catch (SnmpException ex)
            {
                Console.WriteLine($"SNMP Error: {ex.Message}");
            }
           
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        // Hàm PingHost
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

        // Hàm GetSnmpData
        static async Task<Dictionary<string, string>?> GetSnmpData(IPAddress address)
        {
            var result = new Dictionary<string, string>();
            var oids = new List<ObjectIdentifier> {
        new ObjectIdentifier(".1.3.6.1.2.1.1.1.0"),    // sysDescr
        new ObjectIdentifier(".1.3.6.1.2.1.1.3.0"),     // sysUpTime
        new ObjectIdentifier(".1.3.6.1.2.1.1.5.0"),     // sysName
        new ObjectIdentifier(".1.3.6.1.2.1.1.6.0"),     // sysLocation
        new ObjectIdentifier(".1.3.6.1.2.1.2.1.0"),     // ifNumber
    };

            // Thêm OID của tất cả các MAC address
            for (int i = 1; i <= 128; i++) // 128 interface
            {
                oids.Add(new ObjectIdentifier($".1.3.6.1.2.1.2.2.1.6.{i}"));
            }

            // Chuyển đổi List<ObjectIdentifier> thành List<Variable>
            var variables = oids.ConvertAll(oid => new Variable(oid));

            try
            {
                var getResponse = await Messenger.GetAsync(VersionCode.V3,
                    new IPEndPoint(address, 161),
                    new OctetString(""),
                    variables);

                if (getResponse != null && getResponse.Count > 0)
                {
                    foreach (var vb in getResponse)
                    {
                        // Chỉ thêm vào result nếu giá trị không null hoặc rỗng
                        if (!string.IsNullOrWhiteSpace(vb.Data.ToString()))
                        {
                            result[vb.Id.ToString()] = vb.Data.ToString();
                        }
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
                if (ex.Message.Contains("authentication failure", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Authentication failed. Please check your SNMP credentials.");
                }
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return null;
            }
        }

        static Dictionary<int, string> GetMacAddresses(Dictionary<string, string> data)
        {
            var macAddresses = new Dictionary<int, string>();

            foreach (var kvp in data)
            {
                if (kvp.Key.StartsWith(".1.3.6.1.2.1.2.2.1.6."))
                {
                    var parts = kvp.Key.Split('.');
                    if (parts.Length > 0 && int.TryParse(parts[parts.Length - 1], out int interfaceIndex))
                    {
                        macAddresses[interfaceIndex] = kvp.Value;
                    }
                }
            }

            return macAddresses;
        }
    }
}
