using System;

namespace MLNetAnomalyDetection.Models
{
    public class NetworkTrafficData
    {
        public float BytesPerSecond { get; set; }
        public float PacketsPerSecond { get; set; }
        public float UniqueIPsContacted { get; set; }
        public float UnusualPortTraffic { get; set; }
        public float OutboundTrafficRatio { get; set; }
    }

    public class NetworkTrafficPrediction
    {
        [Microsoft.ML.Data.ColumnName("PredictedLabel")]
        public bool IsAnomaly { get; set; }

        [Microsoft.ML.Data.ColumnName("Score")]
        public float Score { get; set; }
    }
}
