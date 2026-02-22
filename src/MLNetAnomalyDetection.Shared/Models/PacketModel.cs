using System;

namespace MLNetAnomalyDetection.Models
{
    public class PacketModel
    {
        public int Number { get; set; }
        public DateTime Time { get; set; }
        public string SourceIp { get; set; } = string.Empty;
        
        private string _resolvedSourceIp = string.Empty;
        public string ResolvedSourceIp
        {
            get => string.IsNullOrEmpty(_resolvedSourceIp) ? SourceIp : _resolvedSourceIp;
            set => _resolvedSourceIp = value;
        }

        public string DestinationIp { get; set; } = string.Empty;
        
        private string _resolvedDestinationIp = string.Empty;
        public string ResolvedDestinationIp
        {
            get => string.IsNullOrEmpty(_resolvedDestinationIp) ? DestinationIp : _resolvedDestinationIp;
            set => _resolvedDestinationIp = value;
        }
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public int Length { get; set; }
        public string Info { get; set; } = string.Empty;
        public byte[]? Payload { get; set; }

        public uint TcpSequenceNumber { get; set; }
        public byte[]? DecryptedPayload { get; set; }

        public string DecryptedText
        {
            get
            {
                if (DecryptedPayload == null || DecryptedPayload.Length == 0) return string.Empty;
                
                var sb = new System.Text.StringBuilder();
                foreach (var b in DecryptedPayload)
                {
                    if (b >= 32 && b <= 126)
                        sb.Append((char)b);
                    else
                        sb.Append('.');
                }
                return sb.ToString();
            }
        }

        public string DecryptedHex
        {
            get
            {
                if (DecryptedPayload == null || DecryptedPayload.Length == 0) return string.Empty;
                return BitConverter.ToString(DecryptedPayload).Replace("-", " ");
            }
        }

        public bool IsHighlighted { get; set; }
    }
}
