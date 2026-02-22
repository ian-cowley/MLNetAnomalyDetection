using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Transforms.TimeSeries;
using MLNetAnomalyDetection.Models;

namespace MLNetAnomalyDetection.Services
{
    public class AnomalyDetectionService
    {
        private readonly MLContext _mlContext;
        private ITransformer? _trainedModel;
        private PredictionEngine<NetworkTrafficData, NetworkTrafficPrediction>? _predictionEngine;
        
        private readonly ConcurrentQueue<PacketModel> _packetBuffer = new ConcurrentQueue<PacketModel>();
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private Task? _aggregationTask;

        public event EventHandler<AnomalyAlertEventArgs>? OnAnomalyDetected;
        public event EventHandler<StatsEventArgs>? OnStatsUpdated;

        public AnomalyDetectionService()
        {
            _mlContext = new MLContext(seed: 0);
        }

        public void IngestPacket(object? sender, PacketModel packet)
        {
            _packetBuffer.Enqueue(packet);
        }

        public void Start()
        {
            TrainInitialModel();
            
            _cts = new CancellationTokenSource();
            _aggregationTask = Task.Run(() => AggregationLoop(_cts.Token));
        }

        public void Stop()
        {
            _cts.Cancel();
            _aggregationTask?.Wait();
        }

        private void TrainInitialModel()
        {
            // Seed it with some normal-looking dummy data for initial baseline
            var dummyData = new List<NetworkTrafficData>();
            var rnd = new Random(42);
            for (int i = 0; i < 60; i++) 
            {
                dummyData.Add(new NetworkTrafficData 
                { 
                    BytesPerSecond = 1000 + (float)rnd.NextDouble() * 500,
                    PacketsPerSecond = 10 + (float)rnd.NextDouble() * 5,
                    UniqueIPsContacted = 2 + (float)rnd.NextDouble() * 2,
                    UnusualPortTraffic = (float)rnd.NextDouble() * 50,
                    OutboundTrafficRatio = 1.0f + (float)rnd.NextDouble() * 0.5f
                });
            }

            var dataView = _mlContext.Data.LoadFromEnumerable(dummyData);

            // Configure PCA Anomaly Detector
            var pipeline = _mlContext.Transforms.Concatenate("Features", 
                    nameof(NetworkTrafficData.BytesPerSecond),
                    nameof(NetworkTrafficData.PacketsPerSecond),
                    nameof(NetworkTrafficData.UniqueIPsContacted),
                    nameof(NetworkTrafficData.UnusualPortTraffic),
                    nameof(NetworkTrafficData.OutboundTrafficRatio))
                .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(featureColumnName: "Features", rank: 3));

            _trainedModel = pipeline.Fit(dataView);
            _predictionEngine = _mlContext.Model.CreatePredictionEngine<NetworkTrafficData, NetworkTrafficPrediction>(_trainedModel);
        }

        private async Task AggregationLoop(CancellationToken token)
        {
            float avgBytes = 1000f;
            float avgPackets = 10f;
            float avgIps = 2f;
            float avgUnusual = 0f;
            float avgRatio = 1f;

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1000, token); // Aggregate every 1 second

                    int bytesThisSecond = 0;
                    int packetsThisSecond = 0;
                    var uniqueIps = new HashSet<string>();
                    int unusualPortBytes = 0;
                    int outboundBytes = 0;
                    int inboundBytes = 0;
                    
                    while (_packetBuffer.TryDequeue(out var packet))
                    {
                        bytesThisSecond += packet.Length;
                        packetsThisSecond++;
                        
                        if (!string.IsNullOrEmpty(packet.DestinationIp)) 
                        {
                            uniqueIps.Add(packet.DestinationIp);
                        }

                        // Whitelist of common ports
                        if (packet.DestinationPort != 80 && packet.DestinationPort != 443 && 
                            packet.DestinationPort != 53 && packet.DestinationPort != 22)
                        {
                            unusualPortBytes += packet.Length;
                        }

                        if (packet.DestinationPort < 1024) outboundBytes += packet.Length;
                        if (packet.SourcePort < 1024) inboundBytes += packet.Length;
                    }

                    float ratio = inboundBytes == 0 ? (outboundBytes > 0 ? 10.0f : 1.0f) : (float)outboundBytes / inboundBytes;

                    var dataPoint = new NetworkTrafficData 
                    { 
                        BytesPerSecond = bytesThisSecond,
                        PacketsPerSecond = packetsThisSecond,
                        UniqueIPsContacted = uniqueIps.Count,
                        UnusualPortTraffic = unusualPortBytes,
                        OutboundTrafficRatio = ratio
                    };

                    // Update moving averages
                    avgBytes = avgBytes * 0.9f + dataPoint.BytesPerSecond * 0.1f;
                    avgPackets = avgPackets * 0.9f + dataPoint.PacketsPerSecond * 0.1f;
                    avgIps = avgIps * 0.9f + dataPoint.UniqueIPsContacted * 0.1f;
                    avgUnusual = avgUnusual * 0.9f + dataPoint.UnusualPortTraffic * 0.1f;
                    avgRatio = avgRatio * 0.9f + dataPoint.OutboundTrafficRatio * 0.1f;

                    // Pre-warm case where engine isn't ready
                    if (_predictionEngine != null)
                    {
                        var prediction = _predictionEngine.Predict(dataPoint);
                        
                        bool isAnomaly = prediction.IsAnomaly;
                        double score = prediction.Score;

                        if (isAnomaly)
                        {
                            string reason = "General Traffic Spike";
                            if (dataPoint.UniqueIPsContacted > avgIps * 3 + 5) reason = "Spike in Unique IPs Contacted";
                            else if (dataPoint.UnusualPortTraffic > avgUnusual * 3 + 1000) reason = "Spike in Unusual Port Traffic";
                            else if (dataPoint.OutboundTrafficRatio > avgRatio * 3 + 2) reason = "Spike in Outbound Traffic Ratio";
                            else if (dataPoint.BytesPerSecond > avgBytes * 3 + 5000) reason = "Spike in Total Bandwidth";

                            OnAnomalyDetected?.Invoke(this, new AnomalyAlertEventArgs
                            {
                                Timestamp = DateTime.Now,
                                BytesPerSecond = bytesThisSecond,
                                PacketsPerSecond = packetsThisSecond,
                                UniqueIPsContacted = uniqueIps.Count,
                                UnusualPortTraffic = unusualPortBytes,
                                OutboundTrafficRatio = ratio,
                                Score = score,
                                Reason = reason
                            });
                        }
                        OnStatsUpdated?.Invoke(this, new StatsEventArgs
                        {
                            Timestamp = DateTime.Now,
                            BytesPerSecond = bytesThisSecond,
                            PacketsPerSecond = packetsThisSecond,
                            UniqueIPsContacted = uniqueIps.Count,
                            UnusualPortTraffic = unusualPortBytes,
                            OutboundTrafficRatio = ratio,
                            IsAnomaly = isAnomaly,
                            Score = score
                        });
                    }
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception)
                {
                    // Ignore transient background exceptions
                }
            }
        }
    }

    public class AnomalyAlertEventArgs : EventArgs
    {
        public DateTime Timestamp { get; set; }
        public float BytesPerSecond { get; set; }
        public int PacketsPerSecond { get; set; }
        public int UniqueIPsContacted { get; set; }
        public int UnusualPortTraffic { get; set; }
        public float OutboundTrafficRatio { get; set; }
        public double Score { get; set; }
        public string Reason { get; set; } = string.Empty;
    }
    
    public class StatsEventArgs : EventArgs
    {
        public DateTime Timestamp { get; set; }
        public float BytesPerSecond { get; set; }
        public int PacketsPerSecond { get; set; }
        public int UniqueIPsContacted { get; set; }
        public int UnusualPortTraffic { get; set; }
        public float OutboundTrafficRatio { get; set; }
        public bool IsAnomaly { get; set; }
        public double Score { get; set; }
    }
}
