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
using Serilog.Context;
using Serilog.Core;
using File = System.IO.File;

namespace PcapReader
{
    class Program
    {
        private static long No = 0;
        private static Dictionary<string, (long no, IPv4Packet packet)> sessions = new Dictionary<string, (long no, IPv4Packet packet)>();

        static void Main(string[] args)
        {
            var dir = @"D:\_NH\Online 20211216\12.16-3";

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

            var pcapng = Directory.GetFiles(dir, "*.pcapng").SingleOrDefault();
            if (pcapng == null)
            {
                Log.Error("File .pcapng not fount or not single");
                return;
            }

            using var reader = IReaderFactory.GetReader(pcapng);
            {
                reader.OnReadPacketEvent += ReaderOnOnReadPacketEvent;
                reader.ReadPackets(CancellationToken.None);
                reader.OnReadPacketEvent -= ReaderOnOnReadPacketEvent;
            }

            Log.Information("ClientHello sessions {Count}", sessions.Count);

            Parallel.ForEach(Directory.GetFiles(dir, "*.DMP"), file =>
            {
                var bytes = ByteArrayToString(File.ReadAllBytes(file), false);
                Log.Information("File loaded {File}", Path.GetFileName(file));

                Parallel.ForEach(sessions, session =>
                {
                    var offset = bytes.IndexOf(session.Key, StringComparison.Ordinal);
                    if (offset > -1)
                        Log.Information("{File} : {SessionId} {No} {SourceAddress} {DestinationAddress} {IndexOf}", Path.GetFileName(file), session.Key, session.Value.no, session.Value.packet.SourceAddress, session.Value.packet.DestinationAddress, offset);
                });

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
