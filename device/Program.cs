using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SimpleSnmpScanner
{
    class Program
    {
        //  // OID constants
        const string SysNameOid = ".1.3.6.1.2.1.1.5.0";// System Name
        const string IfPhysAddressOid = ".1.3.6.1.2.1.2.2.1.6";// Interface Physical Address (MAC)
        const string SysDescrOid = ".1.3.6.1.2.1.1.1.0";// System Description
        //const string SysContactOid = ".1.3.6.1.2.1.1.4.0"; 
        const string SysLocationOid = ".1.3.6.1.2.1.1.6.0";// System Location
        const string IfNumberOid = ".1.3.6.1.2.1.2.1.0";// Interface Number
        const string Dot1dBasePortIfIndexOid = ".1.3.6.1.2.1.17.1.4.1.2"; //Bridge MIB Port to Interface Index
        const string Dot1dTpFdbAddressOid = ".1.3.6.1.2.1.17.4.3.1.1";   // Bridge MIB MAC Address Table
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
                //1. Check online status
                bool isOnline = PingHost(address);
                Console.WriteLine($"Status: {(isOnline ? "Online" : "Offline")}");

                if (!isOnline) return;

                //2. Retrieve SNMP data
                var result = await GetSnmpData(address);

                if (result != null)
                {
                    Console.WriteLine("Device Name: " + result[SysNameOid]);
                    Console.WriteLine("MAC Address: " + result[IfPhysAddressOid]);
                    Console.WriteLine("Description: " + result[SysDescrOid]);
                    //Console.WriteLine("Contact: " + result[SysContactOid]);
                    Console.WriteLine("Location: " + result[SysLocationOid]);
                    Console.WriteLine("Number of interfaces: " + result[IfNumberOid]);
                    if (result.ContainsKey(".1.3.6.1.2.1.1.3.0"))
                        Console.WriteLine("Uptime: " + result[".1.3.6.1.2.1.1.3.0"]);

                    // 3. Retrieve switch and port information
                    if (result.ContainsKey(IfPhysAddressOid))
                    {
                        var macAddress = result[IfPhysAddressOid].Replace(":", ""); // Chuẩn hóa MAC address

                        // 3.1 Get interface index
                        int interfaceIndex = GetInterfaceIndex(macAddress, result);
                        if (interfaceIndex > 0)
                        {
                            Console.WriteLine("Interface Index: " + interfaceIndex);

                            // 3.2Get switch information from dot1dTpFdb table
                            var switchInfo = await GetSwitchInfo(address, interfaceIndex);
                            if (switchInfo is (string switchName, string switchIpAddress, string switchMacAddress, string switchPort))
                            {
                                Console.WriteLine($"Switch Name: {switchName}, IP: {switchIpAddress}, MAC: {switchMacAddress}, Port: {switchPort}");
                            }
                            else
                            {
                                Console.WriteLine("Failed to retrieve switch information.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Failed to retrieve interface index.");
                        }
                    }
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
            new ObjectIdentifier(Dot1dBasePortIfIndexOid) //lấy thông tin cổng switch
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
        //Lấy chỉ số interface từ MAC address
        static int GetInterfaceIndex(string macAddress, Dictionary<string, string> data)
        {
            foreach (var kvp in data)
            {
                if (kvp.Key.StartsWith(IfPhysAddressOid) && kvp.Value.Replace(":", "") == macAddress)
                {
                    return int.Parse(kvp.Key.Split('.').Last()); // Trả về chỉ số interface
                }
            }
            return -1; // not found
        }

        // Lấy thông tin switch
        static async Task<(string Name, string IpAddress, string MacAddress, string Port)?> GetSwitchInfo(IPAddress address, int interfaceIndex)
        {
            var oids = new List<ObjectIdentifier> {
                new ObjectIdentifier(".1.3.6.1.2.1.17.4.3.1.1"),  // dot1dTpFdbAddress
                new ObjectIdentifier(".1.3.6.1.2.1.17.1.4.1.2")   // dot1dBasePortIfIndex
            };

            var variables = oids.ConvertAll(oid => new Variable(oid));
            var getResponse = await Messenger.GetAsync(VersionCode.V3, new IPEndPoint(address, 161), 
                new OctetString("public"), variables);

            if (getResponse != null)
            {
                foreach (var vb in getResponse)
                {
                    if (vb.Id.ToString().StartsWith(Dot1dBasePortIfIndexOid) && vb.Data is Integer32 data && data.ToInt32() == interfaceIndex)
                    {
                        string switchPortIndex = vb.Id.ToString().Split('.').Last();
                        string switchIpAddress = "Unknown";
                        string switchMacAddress = string.Empty;

                        // Tìm MAC address của switch port
                        var switchPortMacOid = new ObjectIdentifier($"{Dot1dTpFdbAddressOid}.{switchPortIndex}");
                        var switchPortMacResponse = await Messenger.GetAsync(VersionCode.V3, new IPEndPoint(address, 161), new OctetString("public"), new List<Variable> { new Variable(switchPortMacOid) });

                        // Kiểm tra switchPortMacResponse trước khi truy cập
                        if (switchPortMacResponse != null && switchPortMacResponse.Count > 0)
                        {
                            switchMacAddress = switchPortMacResponse[0].Data.ToString().Replace(":", "");

                            // Lấy thông tin switch từ ARP table (giả sử có ARP table)
                            var arpTable = GetArpTable(address);
                            if (!arpTable.TryGetValue(PhysicalAddress.Parse(switchMacAddress), out IPAddress switchIp))
                            {
                                switchIpAddress = "Unknown"; // MAC address không tìm thấy trong ARP table
                            }
                            else
                            {
                                switchIpAddress = switchIp.ToString();
                            }
                        }
                        else
                        {
                            Console.WriteLine("Failed to retrieve switch MAC address.");
                            return null;
                        }

                        // Trả về thông tin switch
                        return ("Switch Name", switchIpAddress, switchMacAddress, switchPortIndex);
                    }
                }
            }
            return null;
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
        
        static Dictionary<PhysicalAddress, IPAddress> GetArpTable(IPAddress ipAddress)
        {
            var arpTable = new Dictionary<PhysicalAddress, IPAddress>();
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            var unicastAddresses = properties.GetActiveTcpConnections().Select(x => x.LocalEndPoint.Address).ToList();
            unicastAddresses.AddRange(properties.GetActiveUdpListeners().Select(x => x.Address).ToList());
            foreach (var unicastAddress in unicastAddresses)
            {
                if (unicastAddress.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (unicastAddress.Equals(ipAddress))
                    {
                        continue;
                    }

                    // Lấy NetworkInterface tương ứng với ipAddress
                    var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                    var networkInterface = networkInterfaces.FirstOrDefault(ni =>
                        ni.GetIPProperties().UnicastAddresses.Any(ua => ua.Address.Equals(ipAddress)));

                    if (networkInterface != null)
                    {
                        // Lấy MAC address
                        var macAddress = networkInterface.GetPhysicalAddress();

                        if (macAddress != null)
                        {
                            arpTable.Add(macAddress, unicastAddress);
                        }
                    }
                }
            }
            return arpTable;
        }
    }
}
