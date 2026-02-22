using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Linq;
using LiveCharts;
using LiveCharts.Wpf;
using MLNetAnomalyDetection.Services;
using MLNetAnomalyDetection.Models;
using System.Windows;

namespace MLNetAnomalyDetection.ViewModels
{
    public class DashboardViewModel : INotifyPropertyChanged
    {
        public ChartValues<double> TrafficValues { get; set; } = new ChartValues<double>();
        public ChartValues<double> AnomalyScores { get; set; } = new ChartValues<double>();

        public ObservableCollection<NetworkAdapterInfo> Adapters { get; set; } = new ObservableCollection<NetworkAdapterInfo>();

        private NetworkAdapterInfo? _selectedAdapter;
        public NetworkAdapterInfo? SelectedAdapter
        {
            get => _selectedAdapter;
            set
            {
                if (_selectedAdapter != value)
                {
                    _selectedAdapter = value;
                    OnPropertyChanged();
                    if (_selectedAdapter != null)
                    {
                        NotifyAdapterChange(_selectedAdapter.Name);
                    }
                }
            }
        }

        public Func<double, string> TrafficFormatter { get; set; } = val => $"{val:F1} KB/s";
        public Func<double, string> ScoreFormatter { get; set; } = val => $"{val:F2}";

        private string _statusText = "Waiting for data...";
        public string StatusText
        {
            get => _statusText;
            set { _statusText = value; OnPropertyChanged(); }
        }

        private int _packetsPerSecond;
        public int PacketsPerSecond
        {
            get => _packetsPerSecond;
            set { _packetsPerSecond = value; OnPropertyChanged(); }
        }

        private int _uniqueIps;
        public int UniqueIps
        {
            get => _uniqueIps;
            set { _uniqueIps = value; OnPropertyChanged(); }
        }

        private int _unusualPortTraffic;
        public int UnusualPortTraffic
        {
            get => _unusualPortTraffic;
            set { _unusualPortTraffic = value; OnPropertyChanged(); }
        }

        private float _outboundRatio;
        public float OutboundRatio
        {
            get => _outboundRatio;
            set { _outboundRatio = value; OnPropertyChanged(); }
        }

        public void AddDataPoint(StatsEventArgs ev)
        {
            double kbps = ev.BytesPerSecond / 1024.0;
            
            TrafficValues.Add(kbps);
            AnomalyScores.Add(ev.Score);

            // Keep only the last 60 seconds
            if (TrafficValues.Count > 60) TrafficValues.RemoveAt(0);
            if (AnomalyScores.Count > 60) AnomalyScores.RemoveAt(0);

            StatusText = ev.IsAnomaly 
                ? $"⚠️ ANOMALY DETECTED | Traffic: {kbps:F1} KB/s | Score: {ev.Score:F2}"
                : $"Normal | Traffic: {kbps:F1} KB/s | Score: {ev.Score:F2}";

            PacketsPerSecond = ev.PacketsPerSecond;
            UniqueIps = ev.UniqueIPsContacted;
            UnusualPortTraffic = ev.UnusualPortTraffic;
            OutboundRatio = ev.OutboundTrafficRatio;
        }

        public void UpdateAdapters(List<NetworkAdapterInfo> adapters)
        {
            Adapters.Clear();
            foreach (var a in adapters)
            {
                Adapters.Add(a);
            }

            // If nothing selected yet, try to find a reasonable default
            if (SelectedAdapter == null)
            {
                SelectedAdapter = Adapters.FirstOrDefault(a => a.IpAddress != "No IP" && a.IpAddress != "127.0.0.1") 
                                 ?? Adapters.FirstOrDefault();
            }
        }

        private void NotifyAdapterChange(string adapterName)
        {
            (System.Windows.Application.Current as App)?.SendIpcMessage(new IPCMessage
            {
                MessageType = "SetAdapter",
                PayloadJson = adapterName
            });
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
