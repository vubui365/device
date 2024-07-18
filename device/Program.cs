using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Linq;
using System.Net.Sockets;

namespace SimpleSnmpScanner
{
    class Program
    {
        // OID constants
        const string SysNameOid = ".1.3.6.1.2.1.1.5.0";       // System Name
        const string IfPhysAddressOid = ".1.3.6.1.2.1.2.2.1.6";  // Interface Physical Address (MAC)
        const string SysDescrOid = ".1.3.6.1.2.1.1.1.0";      // System Description
        const string SysLocationOid = ".1.3.6.1.2.1.1.6.0";     // System Location
        const string IfNumberOid = ".1.3.6.1.2.1.2.1.0";      // Interface Number

        // OIDs for retrieving switch information (Bridge MIB)
        const string Dot1dBasePortIfIndexOid = ".1.3.6.1.2.1.17.1.4.1.2"; // Bridge MIB Port to Interface Index
        const string Dot1dTpFdbAddressOid = ".1.3.6.1.2.1.17.4.3.1.1";   // Bridge MIB MAC Address Table

        static async Task Main()
        {
            Console.WriteLine("Please enter IPv4 address:");
            string? ipAddress = Console.ReadLine();

            if (!IPAddress.TryParse(ipAddress, out IPAddress? address))
            {
                Console.WriteLine("Invalid IPv4 address.");
                return;
            }

            try
            {
                // 1. Check if the device is online using ping
                bool isOnline = PingHost(address);
                Console.WriteLine($"Status: {(isOnline ? "Online" : "Offline")}");

                if (!isOnline) return;

                // 2. Retrieve SNMP data from the device
                var result = await GetSnmpData(address);

                // Display device information
                if (result != null)
                {
                    DisplayDeviceInfo(result);
                    await PrintSwitchInfo(result, address);
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

        // Function to check if the host is online by pinging it
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

        // Function to retrieve SNMP data from the device
        static async Task<Dictionary<string, string>?> GetSnmpData(IPAddress address)
        {
            var result = new Dictionary<string, string>();
            var oids = new List<ObjectIdentifier> {
                new ObjectIdentifier(SysNameOid),
                new ObjectIdentifier(SysDescrOid),
                new ObjectIdentifier(SysLocationOid),
                new ObjectIdentifier(IfNumberOid),
                new ObjectIdentifier(Dot1dBasePortIfIndexOid) // Get switch port information
            };

            // Add OIDs for all MAC addresses (assuming a maximum of 128 interfaces)
            for (int i = 1; i <= 128; i++)
            {
                oids.Add(new ObjectIdentifier($"{IfPhysAddressOid}.{i}"));
            }

            // Convert List<ObjectIdentifier> to List<Variable>
            var variables = oids.ConvertAll(oid => new Variable(oid));

            try
            {
                var getResponse = await Messenger.GetAsync(VersionCode.V3,
                    new IPEndPoint(address, 161),
                    new OctetString(""),  // Community string (empty for no authentication)
                    variables);

                if (getResponse != null && getResponse.Count > 0)
                {
                    foreach (var vb in getResponse)
                    {
                        // Only add to result if the value is not null or empty
                        if (vb.Data != null && !string.IsNullOrWhiteSpace(vb.Data.ToString()))
                        {
                            result[vb.Id.ToString()] = vb.Data.ToString();
                        }
                        else
                        {
                            Console.WriteLine($"Warning: OID {vb.Id} returned no value.");
                        }
                    }
                }

                return result;
            }
            catch (Lextm.SharpSnmpLib.Messaging.TimeoutException ex)
            {
                Console.WriteLine($"Timeout Error: {ex.Message}");

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
            return null;
        }

        // Function to display device information
        static void DisplayDeviceInfo(Dictionary<string, string> data)
        {
            Console.WriteLine("Device Name: " + data.GetValueOrDefault(SysNameOid, "N/A"));
            Console.WriteLine("Description: " + data.GetValueOrDefault(SysDescrOid, "N/A"));
            Console.WriteLine("Location: " + data.GetValueOrDefault(SysLocationOid, "N/A"));
            Console.WriteLine("Number of interfaces: " + data.GetValueOrDefault(IfNumberOid, "N/A"));
            Console.WriteLine("Uptime: " + data.GetValueOrDefault(".1.3.6.1.2.1.1.3.0", "N/A")); // sysUpTime
        }

        // Function to print switch information
        static async Task PrintSwitchInfo(Dictionary<string, string> data, IPAddress address)
        {
            if (data.ContainsKey(IfPhysAddressOid))
            {
                var macAddress = data[IfPhysAddressOid].Replace(":", ""); // Normalize MAC address

                // Get the interface index associated with the device's MAC address
                int interfaceIndex = GetInterfaceIndex(macAddress, data);
                if (interfaceIndex > 0)
                {
                    Console.WriteLine("Interface Index: " + interfaceIndex);

                    // Get switch information from the dot1dTpFdb table
                    var switchInfoTask = GetSwitchInfo(address, interfaceIndex); // Get the Task
                    var switchInfo = await switchInfoTask; // Wait for the Task to complete

                    // Check and print switch information
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

        // Function to get interface index from MAC address
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

        // Function to get switch information
        static async Task<(string Name, string IpAddress, string MacAddress, string Port)?> GetSwitchInfo(IPAddress address, int interfaceIndex)
        {
            var oids = new List<ObjectIdentifier> {
                new ObjectIdentifier(Dot1dTpFdbAddressOid),  // MAC address table
                new ObjectIdentifier(Dot1dBasePortIfIndexOid) // Port to interface index mapping
            };

            var variables = oids.ConvertAll(oid => new Variable(oid));
            var getResponse = await Messenger.GetAsync(VersionCode.V3, new IPEndPoint(address, 161),
                new OctetString("public"), variables);

            if (getResponse != null)
            {
                foreach (var vb in getResponse)
                {
                    // Check if the OID is for the base port to interface index mapping
                    // and if the interface index matches the one we're looking for
                    if (vb.Id.ToString().StartsWith(Dot1dBasePortIfIndexOid) && vb.Data is Integer32 data && data.ToInt32() == interfaceIndex)
                    {
                        var switchPortIndex = vb.Id.ToString().Split('.').Last();
                        string switchIpAddress = "Unknown";
                        string switchMacAddress = string.Empty;

                        // Get the MAC address of the switch port
                        var switchPortMacOid = new ObjectIdentifier($"{Dot1dTpFdbAddressOid}.{switchPortIndex}");
                        var switchPortMacResponse = await Messenger.GetAsync(VersionCode.V3, new IPEndPoint(address, 161), new OctetString("public"), new List<Variable> { new Variable(switchPortMacOid) });

                        // Check if the MAC address response is valid
                        if (switchPortMacResponse != null && switchPortMacResponse.Count > 0)
                        {
                            switchMacAddress = switchPortMacResponse[0].Data.ToString().Replace(":", "");

                            // Retrieve switch information from the ARP table
                            var arpTable = GetArpTable(address);
                            if (arpTable.TryGetValue(PhysicalAddress.Parse(switchMacAddress), out IPAddress switchIp))
                            {
                                switchIpAddress = switchIp.ToString();
                            }
                            else
                            {
                                Console.WriteLine("Switch MAC address not found in ARP table.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Failed to retrieve switch MAC address.");
                        }

                        // Return switch information (name is set to "Unknown" as it's not available via SNMP)
                        return ("Unknown", switchIpAddress, switchMacAddress, switchPortIndex);
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
        //Retrieves the ARP table for the specified IP address.
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

                    // Find the NetworkInterface associated with the ipAddress
                    var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                    var networkInterface = networkInterfaces.FirstOrDefault(ni =>
                        ni.GetIPProperties().UnicastAddresses.Any(ua => ua.Address.Equals(ipAddress)));

                    if (networkInterface != null)
                    {
                        // Get MAC address
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
