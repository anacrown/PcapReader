using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using PcapngUtils;
using PcapngUtils.Common;
using Serilog;
using File = System.IO.File;

namespace PcapReader
{
    class Program
    {
        private static long No = 0;
        private static Dictionary<string, (long no, IPv4Packet packet)> sessions = new Dictionary<string, (long no, IPv4Packet packet)>();

        static void Main(string[] args)
        {
            var dir = @"D:\R\2";
            var sslkeylogfile = Path.Combine(dir, "SSLKEYLOGFILE.txt");
            var pcapng = Directory.GetFiles(dir, "*.pcapng").SingleOrDefault();

            if (pcapng == null)
            {
                Log.Error("File .pcapng not found or not single");
                return;
            }

            if (!File.Exists(sslkeylogfile))
            {
                Log.Error("File SSLKEYLOGFILE.txt not found");
                return;
            }

            Log.Logger = new LoggerConfiguration()
                .Enrich.WithAssemblyName()
                .Enrich.WithAssemblyVersion()
                .Enrich.WithMemoryUsage()
                .Enrich.WithProperty("Guid", Guid.NewGuid())
                .Enrich.WithProperty("Root", dir)
                .WriteTo.Console()
                .WriteTo.File("log.txt", rollingInterval: RollingInterval.Day)
                .WriteTo.Seq("http://localhost:5341")
                .CreateLogger();
           
            using var reader = IReaderFactory.GetReader(pcapng);
            {
                reader.OnReadPacketEvent += ReaderOnOnReadPacketEvent;
                reader.ReadPackets(CancellationToken.None);
                reader.OnReadPacketEvent -= ReaderOnOnReadPacketEvent;
            }
            
            Log.Information("ClientHello sessions {Count}", sessions.Count);
            if (File.Exists(sslkeylogfile))
            {
                foreach (var key in File.ReadAllLines(sslkeylogfile)
                    .Where(l => l.StartsWith("CLIENT_RANDOM"))
                    .Select(l => l.Split(' ').Last().Trim())
                    .Reverse())
                {
                    if (sessions.ContainsKey(key)) continue;

                    sessions.Add(key, default);
                    Log.Information("CLIENT_RANDOM: {Key}", key);
                }
            }

            Parallel.ForEach(Directory.GetFiles(dir, "*.DMP"), file =>
            {
                var bytes = ByteArrayToString(File.ReadAllBytes(file), false);
                Log.Information("File loaded {File}", Path.GetFileName(file));

                var txtFile = $"{Path.GetFileNameWithoutExtension(file)}.txt";
                File.WriteAllText(Path.Combine(dir, txtFile), bytes);
                Log.Information("File saved {TXTFile}", Path.GetFileName(txtFile));

                Parallel.ForEach(sessions, session =>
                {
                    var offset = bytes.IndexOf(session.Key, StringComparison.Ordinal);
                    if (offset <= -1) return;

                    offset /= 2;

                    if (session.Value != default)
                        Log.Information("{File} : {SessionId} {No} {SourceAddress} {DestinationAddress} {IndexOf}",
                            Path.GetFileName(file), session.Key, session.Value.no,
                            session.Value.packet.SourceAddress,
                            session.Value.packet.DestinationAddress, offset.ToString("X4"));
                    else
                        Log.Information("{File} : {SessionId} {IndexOf}", Path.GetFileName(file), session.Key,
                            offset.ToString("X4"));
                });

                // var pattern = new Regex("300000(.{96})200000");
                // Parallel.ForEach(sessions, session =>
                // {
                //     foreach (Match match in pattern.Matches(bytes))
                //     {
                //         Log.Information("{File} [FOUNT BY REGEX] : {SessionId} 0x{IndexOf}", Path.GetFileName(file), match.Groups[1].Value, match.Index.ToString("X4"));
                //     }
                // });
            });
        }

        private static void ReaderOnOnReadPacketEvent(object context, IPacket packet)
        {
            No++;

            var ipv4p = (Packet.ParsePacket(LinkLayers.Ethernet, packet.Data) as EthernetPacket)?.PayloadPacket as IPv4Packet;
            if (ipv4p == null || ipv4p.Protocol != IPProtocolType.TCP) return;

            var body = ipv4p.PayloadPacket.Bytes.Skip(ipv4p.Header.Length).ToArray();
            if (body.Length == 0) return;

            var hendshake = Get(body, 0, 1) == 0x16;
            if (!hendshake) return;

            var clientHello = Get(body, 5, 1) == 0x01;
            if (!clientHello) return;

            var sessionId = new byte[32];
            Array.Copy(body, 44, sessionId, 0, 32);

            var strSessionId = ByteArrayToString(sessionId, false);
            // Console.WriteLine($"{No}: SessionId {strSessionId} {ipv4p.SourceAddress} {ipv4p.DestinationAddress}");

            if (!sessions.ContainsKey(strSessionId))
                sessions.Add(strSessionId, (No, ipv4p));
        }

        static long Get(byte[] b, int offset, int length)
        {
            var counter = 0;
            long result = 0;

            while (counter < length)
            {
                result <<= 8;
                result |= b[offset + counter];

                counter++;
            }

            return result;
        }

        static string ByteArrayToString(byte[] ba, bool format = true)
        {
            var hex = new StringBuilder(ba.Length * 2);
            var counter = 0;
            foreach (var b in ba)
            {
                counter++;
                hex.AppendFormat("{0:x2}", b);

                if (format)
                {
                    hex.Append(" ");

                    if (counter == 8)
                        hex.Append(" ");

                    if (counter == 16)
                    {
                        hex.Append(Environment.NewLine);
                        counter = 0;
                    }
                }
            }

            return hex.ToString();
        }
    }
}
