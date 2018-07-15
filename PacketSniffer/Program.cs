using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Newtonsoft.Json;
using PacketDotNet;
using PacketSniffer.Extensions;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using OpenFlags = System.Security.Cryptography.X509Certificates.OpenFlags;

namespace PacketSniffer {
    class Program {
        private SnifferSettings _settings;
        
        private const int AF_INET = 2;// Address family for IPV4

        static void Main(string[] args) {
            new Program().Run();
            Console.ReadLine();
        }


        private void Run() {
            var settingsFileName = $"{AppDomain.CurrentDomain.FriendlyName}.json";
            _settings = LoadSettings(settingsFileName);

            WinPcapDevice device = null;
            var devices = WinPcapDeviceList.Instance.Where(x => x.Addresses.Any(address => address.Addr.sa_family == AF_INET)).ToList();
            if (_settings.DeviceIp.Equals(IPAddress.None)) {
                var i = 0;
                foreach (var dev in devices) {
                    Console.WriteLine($"{i++}) {dev.Interface.FriendlyName} {dev.Description} ({string.Join(", ", dev.Addresses.Where(x => x.Addr.ipAddress != null).Select(x => x.Addr.ipAddress))})");
                }
                i = int.Parse(Console.ReadLine());
                device = devices[i];
            }
            else {
                foreach (var dev in devices) {
                    var address = GetIPV4SockAddr(dev);
                    if (address.Addr.ipAddress.Equals(_settings.DeviceIp)) {
                        device = dev;
                        Console.WriteLine($"Found device for {address.Addr.ipAddress}!");
                        break;
                    }
                }
                if (device == null) {
                    Console.WriteLine($"Couldn't find device with address {_settings.deviceIp}.");
                    return;
                }
            }

            if (device == null) {
                Console.WriteLine("Couldn't find specified device");
                return;
            }
            
            device.OnPacketArrival += device_OnPacketArrival;
            Console.WriteLine($"opening {device.Interface.FriendlyName}");
            device.Open(DeviceMode.Promiscuous, 1000);
            
            LoadSettings(_settings, device);
            
            //todo add more commands, packetwatches esp.
            var input = Console.ReadLine();
            while (input != "quit") {
                var command = input.Split(" ")[0].ToLower();
                var args = input.Split(" ").Skip(1).ToArray();
                var rest = String.Join(" ", args);
                switch (command) {
                    case "filter":
                        _settings.filter = rest;
                        LoadSettings(_settings, device);
                        break;
                    case "load":
                    case "reload":
                        var fileName = !string.IsNullOrEmpty(rest) ? rest : settingsFileName;
                        _settings = LoadSettings(fileName);
                        Console.WriteLine($"Settings loaded from {fileName}!");
                        break;
                    case "save":
                        SaveSettings(settingsFileName, _settings);
                        Console.WriteLine($"Settings saved to {settingsFileName}!");
                        break;
                }

                if (_settings.autoSave) {
                    SaveSettings(settingsFileName, _settings);
                }

                input = Console.ReadLine();
            }
        }

        private SnifferSettings LoadSettings(string fileName, ICaptureDevice device = null) {
            var jsonSettings = File.Exists(fileName) ? File.ReadAllText(fileName) : null;
            var settings = !string.IsNullOrEmpty(jsonSettings) ? JsonConvert.DeserializeObject<SnifferSettings>(jsonSettings) : new SnifferSettings();
            if (device != null && settings.filter != null) {
                LoadSettings(settings, device);
            }
            return settings;
        }

        private SnifferSettings LoadSettings(SnifferSettings settings, ICaptureDevice device) {
            if (device != null && _settings.filter != null && device.Filter != settings.filter) {
                device.StopCapture();
                device.Filter = settings.filter;
                device.StartCapture();
            }
            return settings;
        }

        private void SaveSettings(string fileName, SnifferSettings settings) {
            var jsonSettings = JsonConvert.SerializeObject(_settings, Formatting.Indented);
            File.WriteAllText(fileName, jsonSettings);
        }

        

        private void device_OnPacketArrival(object sender, CaptureEventArgs e) {
            var time = e.Packet.Timeval.Date;
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            IpPacket ip = (IpPacket)Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data).Extract(typeof(IpPacket));
            TcpPacket tcpPacket = (TcpPacket)Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data).Extract(typeof(TcpPacket));
            var fromServer = !ip.SourceAddress.IsInternal();

            if (tcpPacket != null) {
                WatchPackets(tcpPacket.PayloadData);
                Console.WriteLine(Log(packet, time, fromServer));
            }
        }

        private string Log(Packet packet, DateTime time, bool isRemote) {
            var sb = new StringBuilder();
            IpPacket ip = (IpPacket)packet.Extract(typeof(IpPacket));
            TcpPacket tcp = (TcpPacket)packet.Extract(typeof(TcpPacket));
            if (tcp.PayloadData?.Length == 0) {
                return null;
            }

            var infoSettings = _settings.packetInfoSettings;
            if (infoSettings.direction) sb.Append($"[{(isRemote ? "S->C" : "C->S")}] ");
            if (infoSettings.timestamp) {
                var format = string.IsNullOrEmpty(infoSettings.timestampFormat) ? "T" : infoSettings.timestampFormat;
                sb.Append($"[{DateTime.Now.ToString(format)}] ");
            }

            if (infoSettings.IpGroup) sb.Append("[");
            if (infoSettings.sourceIp) sb.Append($"{ip.SourceAddress}");
            if (infoSettings.sourcePort) sb.Append($":port");//todo
            if (infoSettings.IpGroup) sb.Append(" -> ");
            if (infoSettings.destIp) sb.Append($"{ip.DestinationAddress}");
            if (infoSettings.destPort) sb.Append($":port");//todo
            if (infoSettings.IpGroup) sb.Append("] ");

            if (infoSettings.tcpLength) sb.Append($"TcpLen={tcp.PayloadData?.Length ?? 0} ");
            if (infoSettings.AnySetting) {
                sb.AppendLine();
            }

            //packet data
            sb.Append($"{BitConverter.ToString(tcp?.PayloadData)}");
            
            return sb.ToString();
        }

        private void WatchPackets(byte[] payload) {
            foreach (var watch in _settings.watchedPackets) {
                var startByteSetting = !string.IsNullOrEmpty(watch.startByte) ? Convert.ToInt32(watch.startByte, 16) : -1;
                if (startByteSetting > 0 && payload.FirstOrDefault() == startByteSetting) {
                    if (watch.foregroundColor.HasValue) Console.ForegroundColor = watch.foregroundColor.Value;
                    if (watch.backgroundColor.HasValue) Console.BackgroundColor = watch.backgroundColor.Value;
                    return;
                }
            }
            Console.ResetColor();
        }


        // Return the first IPv4 address found for the device
        private PcapAddress GetIPV4SockAddr(WinPcapDevice device) {
            foreach (PcapAddress address in device.Addresses) {
                if (address.Addr.sa_family == AF_INET) {
                    return address;
                }
            }
            return null;
        }

    }
}