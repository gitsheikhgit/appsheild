using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace AppShield.Service.Discovery;

public class MdnsAdvertiser : IDisposable
{
    private const int MdnsPort = 5353;
    private static readonly IPAddress MdnsMulticastIp = IPAddress.Parse("224.0.0.251");
    private const int ServicePort = 54120;
    private const string ServiceType = "_appshield._tcp.local";

    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;
    private Task? _broadcastTask;

    public void Start()
    {
        _cts = new CancellationTokenSource();

        try
        {
            _udpClient = new UdpClient();
            _udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));

            try
            {
                _udpClient.JoinMulticastGroup(MdnsMulticastIp);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MdnsAdvertiser] Multicast join notice: {ex.Message}");
            }

            _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
            _broadcastTask = Task.Run(() => PeriodicAnnounceAsync(_cts.Token));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MdnsAdvertiser] Initialization notice: {ex.Message}");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        _udpClient?.Dispose();
        _udpClient = null;
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        var targetEndpoint = new IPEndPoint(MdnsMulticastIp, MdnsPort);

        while (!ct.IsCancellationRequested && _udpClient != null)
        {
            try
            {
                var result = await _udpClient.ReceiveAsync(ct);
                string packetStr = Encoding.ASCII.GetString(result.Buffer);

                // If query asks for appshield or standard mdns query
                if (packetStr.Contains("_appshield") || packetStr.Contains("_tcp"))
                {
                    byte[] response = BuildMdnsResponsePacket();
                    await _udpClient.SendAsync(response, response.Length, targetEndpoint);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task PeriodicAnnounceAsync(CancellationToken ct)
    {
        var targetEndpoint = new IPEndPoint(MdnsMulticastIp, MdnsPort);

        while (!ct.IsCancellationRequested && _udpClient != null)
        {
            try
            {
                byte[] response = BuildMdnsResponsePacket();
                await _udpClient.SendAsync(response, response.Length, targetEndpoint);
            }
            catch
            {
            }

            try
            {
                await Task.Delay(30000, ct); // Announce every 30 seconds
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private static byte[] BuildMdnsResponsePacket()
    {
        string host = Environment.MachineName.ToLowerInvariant();
        string instanceName = $"{host}._appshield._tcp.local";
        string targetHost = $"{host}.local";

        var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // DNS Header
        writer.Write((ushort)0); // Transaction ID
        writer.Write((byte)0x84); // Flags: Response, Authoritative
        writer.Write((byte)0x00);
        writer.Write(IPAddress.HostToNetworkOrder((short)0)); // QDCOUNT (Questions)
        writer.Write(IPAddress.HostToNetworkOrder((short)3)); // ANCOUNT (Answers: PTR, SRV, TXT)
        writer.Write(IPAddress.HostToNetworkOrder((short)0)); // NSCOUNT
        writer.Write(IPAddress.HostToNetworkOrder((short)1)); // ARCOUNT (Additional: A record)

        // 1. Answer: PTR Record (_appshield._tcp.local -> instanceName)
        WriteDnsName(writer, ServiceType);
        writer.Write(IPAddress.HostToNetworkOrder((short)12)); // Type PTR
        writer.Write(IPAddress.HostToNetworkOrder((short)0x0001)); // Class IN
        writer.Write(IPAddress.HostToNetworkOrder(120)); // TTL 120s
        byte[] ptrRdata = EncodeDnsName(instanceName);
        writer.Write(IPAddress.HostToNetworkOrder((short)ptrRdata.Length));
        writer.Write(ptrRdata);

        // 2. Answer: SRV Record (instanceName -> port 54120, target targetHost)
        WriteDnsName(writer, instanceName);
        writer.Write(IPAddress.HostToNetworkOrder((short)33)); // Type SRV
        writer.Write(IPAddress.HostToNetworkOrder((short)0x0001)); // Class IN
        writer.Write(IPAddress.HostToNetworkOrder(120)); // TTL
        byte[] srvTarget = EncodeDnsName(targetHost);
        int srvLength = 6 + srvTarget.Length;
        writer.Write(IPAddress.HostToNetworkOrder((short)srvLength));
        writer.Write(IPAddress.HostToNetworkOrder((short)0)); // Priority
        writer.Write(IPAddress.HostToNetworkOrder((short)0)); // Weight
        writer.Write((byte)(ServicePort >> 8)); // Port high byte
        writer.Write((byte)(ServicePort & 0xFF)); // Port low byte
        writer.Write(srvTarget);

        // 3. Answer: TXT Record (instanceName -> txt properties)
        WriteDnsName(writer, instanceName);
        writer.Write(IPAddress.HostToNetworkOrder((short)16)); // Type TXT
        writer.Write(IPAddress.HostToNetworkOrder((short)0x0001)); // Class IN
        writer.Write(IPAddress.HostToNetworkOrder(120)); // TTL
        byte[] txtData = Encoding.UTF8.GetBytes("version=1.0.0");
        writer.Write(IPAddress.HostToNetworkOrder((short)(txtData.Length + 1)));
        writer.Write((byte)txtData.Length);
        writer.Write(txtData);

        // 4. Additional: A Record (targetHost -> local IP)
        WriteDnsName(writer, targetHost);
        writer.Write(IPAddress.HostToNetworkOrder((short)1)); // Type A
        writer.Write(IPAddress.HostToNetworkOrder((short)0x0001)); // Class IN
        writer.Write(IPAddress.HostToNetworkOrder(120)); // TTL
        writer.Write(IPAddress.HostToNetworkOrder((short)4)); // Length 4 bytes
        var localIp = GetLocalIPv4();
        writer.Write(localIp.GetAddressBytes());

        return ms.ToArray();
    }

    private static IPAddress GetLocalIPv4()
    {
        try
        {
            foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (iface.OperationalStatus != OperationalStatus.Up ||
                    iface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                foreach (var ip in iface.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.Address;
                    }
                }
            }
        }
        catch
        {
        }
        return IPAddress.Loopback;
    }

    private static void WriteDnsName(BinaryWriter writer, string domainName)
    {
        writer.Write(EncodeDnsName(domainName));
    }

    private static byte[] EncodeDnsName(string domainName)
    {
        var ms = new MemoryStream();
        string[] labels = domainName.TrimEnd('.').Split('.');
        foreach (var label in labels)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0); // Terminating null
        return ms.ToArray();
    }
}
