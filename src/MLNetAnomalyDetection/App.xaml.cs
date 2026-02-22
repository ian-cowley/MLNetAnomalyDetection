using System;
using System.Drawing;
using System.Linq;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using H.NotifyIcon;
using H.NotifyIcon.Core;
using MLNetAnomalyDetection.Services;
using MLNetAnomalyDetection.Models;

using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MLNetAnomalyDetection.ViewModels;
using MLNetAnomalyDetection.Views;

namespace MLNetAnomalyDetection
{
    public partial class App : System.Windows.Application
    {
        private TaskbarIcon? _notifyIcon;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private DashboardViewModel _dashboardViewModel = new DashboardViewModel();
        private Dashboard? _dashboardWindow;
        private NamedPipeClientStream? _pipeClient;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            _dashboardWindow = new Dashboard(_dashboardViewModel);
            
            _notifyIcon = (TaskbarIcon)FindResource("NotifyIcon");
            _notifyIcon.ForceCreate();
            
            _notifyIcon.TrayLeftMouseUp += (s, args) => 
            {
                _dashboardWindow.Show();
                _dashboardWindow.Activate();
            };
            
            UpdateTrayIcon(false); // Initial state

            InitializeServices();
        }

        private void InitializeServices()
        {
            // Connect to Background Service via Named Pipes
            Task.Run(() => ConnectToPipeServer(_cts.Token), _cts.Token);
        }

        private async Task ConnectToPipeServer(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                NamedPipeClientStream? client = null;
                try
                {
                    _pipeClient = new NamedPipeClientStream(".", "MLNetAnomalyDetectionPipe", PipeDirection.InOut, PipeOptions.Asynchronous);
                    
                    Dispatcher.Invoke(() => _notifyIcon!.ToolTipText = "Connecting to Background Service...");
                    
                    await _pipeClient.ConnectAsync(token);

                    Dispatcher.Invoke(() => 
                    {
                        _notifyIcon!.ToolTipText = "Connected! Waiting for traffic stats...";
                    });

                    using var reader = new StreamReader(_pipeClient);
                    while (!token.IsCancellationRequested && _pipeClient.IsConnected)
                    {
                        var line = await reader.ReadLineAsync();
                        if (string.IsNullOrEmpty(line)) break; // Disconnected

                        var msg = JsonSerializer.Deserialize<IPCMessage>(line);
                        if (msg != null)
                        {
                            HandleIpcMessage(msg);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception)
                {
                    Dispatcher.Invoke(() => _notifyIcon!.ToolTipText = "Service Disconnected. Retrying...");
                }
                finally
                {
                    _pipeClient?.Dispose();
                    _pipeClient = null;
                }

                if (!token.IsCancellationRequested)
                {
                    await Task.Delay(2000, token); // Pause before reconnecting
                }
            }
        }

        private void HandleIpcMessage(IPCMessage msg)
        {
            Dispatcher.Invoke(() =>
            {
                if (msg.MessageType == "Stats")
                {
                    var ev = JsonSerializer.Deserialize<StatsEventArgs>(msg.PayloadJson);
                    if (ev == null) return;

                    _dashboardViewModel.AddDataPoint(ev);

                    _notifyIcon!.ToolTipText = $"Traffic: {ev.BytesPerSecond / 1024.0:F1} KB/s | {ev.PacketsPerSecond} pkts/s\nInbound/Outbound: {ev.OutboundTrafficRatio:F2}\nStatus: {(ev.IsAnomaly ? "Anomaly!" : "Normal")}";
                    if (!ev.IsAnomaly)
                    {
                        UpdateTrayIcon(false);
                    }
                }
                else if (msg.MessageType == "Anomaly")
                {
                    var ev = JsonSerializer.Deserialize<AnomalyAlertEventArgs>(msg.PayloadJson);
                    if (ev == null) return;

                    UpdateTrayIcon(true);
                    _notifyIcon!.ShowNotification("Network Anomaly Detected!", 
                        $"Reason: {ev.Reason}\nTraffic Spike: {ev.BytesPerSecond / 1024.0:F1} KB/s\nScore: {ev.Score:F2}", 
                        NotificationIcon.Warning);
                }
                else if (msg.MessageType == "Adapters")
                {
                    var adapters = JsonSerializer.Deserialize<List<NetworkAdapterInfo>>(msg.PayloadJson);
                    if (adapters != null)
                    {
                        _dashboardViewModel.UpdateAdapters(adapters);
                    }
                }
            });
        }

        public void SendIpcMessage(IPCMessage msg)
        {
            if (_pipeClient == null || !_pipeClient.IsConnected) return;

            try
            {
                var json = JsonSerializer.Serialize(msg) + "\n";
                var bytes = System.Text.Encoding.UTF8.GetBytes(json);
                _pipeClient.Write(bytes, 0, bytes.Length);
                _pipeClient.Flush();
            }
            catch (Exception ex)
            {
                // Failed to send
            }
        }

        private void UpdateTrayIcon(bool isAnomaly)
        {
            if (_notifyIcon == null) return;

            // Generate an icon dynamically so we don't need external files
            int size = System.Windows.Forms.SystemInformation.SmallIconSize.Width;
            using var bmp = new Bitmap(size, size);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

            // Clear background
            g.Clear(Color.Transparent);

            // Draw circle
            var rect = new Rectangle(2, 2, size - 4, size - 4);
            using var brush = new SolidBrush(isAnomaly ? Color.Red : Color.DodgerBlue);
            g.FillEllipse(brush, rect);

            if (isAnomaly)
            {
                // Draw a white exclamation mark or cross
                using var pen = new Pen(Color.White, 2f);
                g.DrawLine(pen, size / 2, 4, size / 2, size - 8);
                g.FillEllipse(Brushes.White, size / 2 - 1, size - 6, 2, 2);
            }

            // Convert Bitmap to Icon
            IntPtr hIcon = bmp.GetHicon();
            try
            {
                var icon = System.Drawing.Icon.FromHandle(hIcon);
                // H.NotifyIcon accepts standard System.Drawing.Icon
                _notifyIcon.Icon = icon;
            }
            finally
            {
                // Clean up native handle (important to avoid memory leak with GDI handles)
                DestroyIcon(hIcon);
            }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        extern static bool DestroyIcon(IntPtr handle);

        private void MenuOpen_Click(object sender, RoutedEventArgs e)
        {
            _dashboardWindow?.Show();
            _dashboardWindow?.Activate();
        }

        private void MenuAbout_Click(object sender, RoutedEventArgs e)
        {
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            System.Windows.MessageBox.Show($"ML.NET Network Anomaly Detection\nVersion: {version}\n\nArchitecture: Split Service/UI\nEngine: ML.NET RandomizedPCA", "About");
        }

        private void MenuExit_Click(object sender, RoutedEventArgs e)
        {
            _cts.Cancel();
            _notifyIcon?.Dispose();
            Shutdown();
        }
    }
}
