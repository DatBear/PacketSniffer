using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Newtonsoft.Json;

namespace PacketSniffer {
    public class SnifferSettings {
        public bool autoSave { get; set; }
        public string filter { get; set; }
        public string deviceIp { get; set; }
        public List<PacketWatchSetting> watchedPackets { get; set; }
        public PacketInfoSettings packetInfoSettings { get; set; }

        [JsonIgnore]
        public IPAddress DeviceIp => !string.IsNullOrEmpty(deviceIp) ? IPAddress.Parse(deviceIp) : IPAddress.None;

        public SnifferSettings() {
            watchedPackets = new List<PacketWatchSetting>();
            packetInfoSettings = new PacketInfoSettings();
        }
    }

    public class PacketWatchSetting {
        public string startByte { get; set; }
        public ConsoleColor? foregroundColor { get; set; }
        public ConsoleColor? backgroundColor { get; set; }
    }

    public class PacketInfoSettings {
        public bool direction { get; set; }
        public bool tcpLength { get; set; }
        public bool sourceIp { get; set; }
        public bool destIp { get; set; }
        public bool sourcePort { get; set; }
        public bool destPort { get; set; }
        public bool timestamp { get; set; }
        public string timestampFormat { get; set; }

        private bool Any(params bool[] settings) {
            return settings.Any(x => x);
        }

        [JsonIgnore]
        public bool IpGroup => Any(sourceIp, destIp, sourcePort, destPort);
        [JsonIgnore]
        public bool AnySetting => Any(direction, tcpLength, sourceIp, destIp, sourcePort, destPort, timestamp);
    }
}