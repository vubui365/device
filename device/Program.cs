using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using Serilog;
using System.Net.Sockets;
Console.OutputEncoding = System.Text.Encoding.UTF8;

// Cấu hình Serilog 
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("snmp_log.txt")
    .CreateLogger();

Console.Write("Mời nhập IP của thiết bị: ");
string ipAddress = Console.ReadLine();

IPEndPoint endPoint = null;

try
{
    IPAddress ip = IPAddress.Parse(ipAddress);
    OctetString community = new OctetString("Admin@123"); // Thay bằng community của bạn nếu khác
    endPoint = new IPEndPoint(ip, 161);

    // Lấy thông tin tên thiết bị
    var vbs = new List<Variable>
    {
        new Variable(new ObjectIdentifier(".1.3.6.1.2.1.1.5.0")) // sysName
    };

    var timeout = 2000;
    var resultGet = Messenger.Get(VersionCode.V2, endPoint, community, vbs, timeout);
    if (resultGet != null)
    {
        Log.Information("--- Thông tin thiết bị ---");
        foreach (var vb in resultGet)
        {
            Log.Information("{Oid} : {Value}", vb.Id, vb.Data);
        }
    }
    else
    {
        Log.Warning("Không nhận được response hoặc timeout khi lấy thông tin thiết bị.");
    }

    // Lấy địa chỉ MAC
    IList<Variable> macAddresses = new List<Variable>();
    Messenger.BulkWalk(VersionCode.V2, endPoint, community, new ObjectIdentifier(".1.3.6.1.2.1.2.2.1.6"), macAddresses, timeout, 10, WalkMode.Default, null, null);

    Log.Information("--- Địa chỉ MAC ---");
    foreach (var vb in macAddresses)
    {
        string mac = vb.Data.ToString();
        if (mac.StartsWith("0x")) // Chỉ lấy địa chỉ MAC hợp lệ
        {
            Log.Information("{Oid} : {Value}", vb.Id, mac.Substring(2).ToUpper()); // Loại bỏ "0x" và chuyển thành chữ hoa
        }
    }

    // Lấy thông tin cổng kết nối
    IList<Variable> resultWalk = new List<Variable>();
    var oids = new List<ObjectIdentifier> {
        new ObjectIdentifier(".1.3.6.1.2.1.2.2.1.2"), // ifDescr
        new ObjectIdentifier(".1.3.6.1.2.1.2.2.1.3"), // ifType
        new ObjectIdentifier(".1.3.6.1.2.1.2.2.1.5"), // ifSpeed
        new ObjectIdentifier(".1.3.6.1.2.1.2.2.1.8")  // ifOperStatus
    };

    foreach (var oid in oids)
    {
        Messenger.BulkWalk(VersionCode.V2, endPoint, community, oid, resultWalk, timeout, 10, WalkMode.Default, null, null);
    }

    Log.Information("--- Thông tin cổng kết nối ---");
    var currentInterface = -1;
    foreach (var vb in resultWalk)
    {
        // Xác định interface hiện tại dựa trên OID
        var oidParts = vb.Id.ToString().Split('.');
        int interfaceIndex = int.Parse(oidParts[oidParts.Length - 1]);
        if (interfaceIndex != currentInterface)
        {
            currentInterface = interfaceIndex;
            Log.Information($"Interface {interfaceIndex}:");
        }

        // Hiển thị thông tin cổng
        switch (oidParts[oidParts.Length - 2])
        {
            case "2":
                Log.Information("  Mô tả: {Value}", vb.Data);
                break;
            case "3":
                Log.Information("  Loại: {Value}", vb.Data);
                break;
            case "5":
                Log.Information("  Tốc độ: {Value}", vb.Data);
                break;
            case "8":
                Log.Information("  Trạng thái: {Value}", vb.Data);
                break;
        }
    }

    // Kiểm tra trạng thái online. 
    bool isOnline = CheckOnlineStatus(ipAddress);
    Log.Information("Trạng thái: {Status}", isOnline ? "Online" : "Offline");
}
catch (SnmpException ex)
{
    Log.Error("Lỗi SNMP: {ErrorMessage}", ex.Message);
}
catch (SocketException ex)
{
    Log.Error("Lỗi kết nối: {ErrorMessage}", ex.Message);
}
catch (System.TimeoutException ex)
{
    Log.Error("Lỗi timeout: {ErrorMessage}", ex.Message);
}
catch (Exception ex)
{
    Log.Error("Lỗi: {ErrorMessage}", ex.Message);
}

static bool CheckOnlineStatus(string ipAddress)
{
    try
    {
        using (Ping ping = new Ping())
        {
            PingReply reply = ping.Send(ipAddress);
            return reply.Status == IPStatus.Success;
        }
    }
    catch
    {
        return false;
    }
}