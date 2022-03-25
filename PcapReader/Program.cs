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

        private static Dictionary<string, (long no, IPv4Packet packet, byte[] sessionId)> sessions =
            new Dictionary<string, (long no, IPv4Packet packet, byte[] sessionId)>();

        static void Main(string[] args)
        {
            var dir = @"D:\R\1";

            Log.Logger = new LoggerConfiguration()
                .Enrich.WithAssemblyName()
                .Enrich.WithAssemblyVersion()
                .Enrich.WithMemoryUsage()
                .Enrich.WithProperty("Guid", Guid.NewGuid())
                .Enrich.WithProperty("Root", dir)
                .WriteTo.Console()
                .WriteTo.File("log.txt", rollingInterval: RollingInterval.Day)
                .WriteTo.Seq("http://localhost:5341")
                .MinimumLevel.Debug()
                .CreateLogger();

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

            using var reader = IReaderFactory.GetReader(pcapng);
            {
                reader.OnReadPacketEvent += ReaderOnOnReadPacketEvent;
                reader.ReadPackets(CancellationToken.None);
                reader.OnReadPacketEvent -= ReaderOnOnReadPacketEvent;
            }

            Parallel.ForEach(Directory.GetFiles(dir, "*.DMP"), file =>
            {
                try
                {
                    // var bytes = ByteArrayToString(File.ReadAllBytes(file), false);
                    // Log.Information("File loaded {File}", Path.GetFileName(file));

                    Parallel.ForEach(sessions, session =>
                    {

                        try
                        {
                            foreach (var offset in Find(file, session.Key, session.Value.sessionId))
                            {
                                Log.Information("{File} : {SessionId} {No} {SourceAddress} {DestinationAddress} {IndexOf}", Path.GetFileName(file), session.Key, session.Value.no, session.Value.packet.SourceAddress, session.Value.packet.DestinationAddress, offset);
                            }
                        }
                        catch (Exception e)
                        {
                            Log.Error(e, e.Message);
                        }
                    });
                }
                catch (Exception e)
                {
                    Log.Error(e, e.Message);
                }
            });
        }

        private static IEnumerable<long> Find(string file, string sessionId, byte[] arr)
        {

            var stream = File.OpenRead(file);
            stream.Seek(0, SeekOrigin.Begin);
            Log.Debug("Find {SessionId} in file {File}", sessionId, Path.GetFileName(file));

            if (arr.Length == 0 || stream.Length < arr.Length)
                yield break;

            var buff = new byte[arr.Length];
            try
            {
                var read = stream.Read(buff);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            while (true)
            {
                if (stream.Position - buff.Length == 0x210)
                {
                    int a = 0 + 12;
                }

                var found = true;
                for (int i = 0; i < buff.Length; i++)
                {
                    if (arr[i] != buff[i])
                    {
                        found = false;
                        break;
                    }
                }

#if DEBUG
                //var strByff = ByteArrayToString(buff);
                //Log.Information("Buffer {buffer} offset {offset} found {found}", strByff, stream.Position-buff.Length, found);
#endif

                if (found)
                    yield return stream.Position - buff.Length;

                for (int i = 1; i < buff.Length; i++)
                    buff[i - 1] = buff[i];

                var b = stream.ReadByte();
                if (b == -1) yield break;
                buff[buff.Length - 1] = (byte)b;
            }
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
            Log.Debug("{No}: SessionId {strSessionId} {ipv4p.SourceAddress} {ipv4p.DestinationAddress}", No, strSessionId, ipv4p.SourceAddress, ipv4p.DestinationAddress);

            if (!sessions.ContainsKey(strSessionId))
                sessions.Add(strSessionId, (No, ipv4p, sessionId));
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

                    // if (counter == 8)
                    //     hex.Append(" ");

                    if (counter == 16)
                    {
                        //hex.Append(Environment.NewLine);
                        counter = 0;
                    }
                }
            }

            return hex.ToString();
        }
    }
}
