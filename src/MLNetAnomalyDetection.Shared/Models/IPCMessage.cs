using System;

namespace MLNetAnomalyDetection.Models
{
    public class IPCMessage
    {
        // "Stats" or "Anomaly"
        public string MessageType { get; set; } = string.Empty;
        public string PayloadJson { get; set; } = string.Empty;
    }
}
