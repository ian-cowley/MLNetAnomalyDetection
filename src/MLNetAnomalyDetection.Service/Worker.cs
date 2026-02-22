using System;
using System.IO.Pipes;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MLNetAnomalyDetection.Models;
using MLNetAnomalyDetection.Services;
using System.Collections.Concurrent;
using System.IO;
using SharpPcap;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace MLNetAnomalyDetection.Service
{
    public class AppSettings
    {
        public string? LastSelectedAdapterName { get; set; }
    }

    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private CaptureService? _captureService;
        private AnomalyDetectionService? _anomalyService;
        private CancellationTokenSource? _pipeCts;
        private Task? _pipeServerTask;
        private readonly ConcurrentDictionary<Guid, NamedPipeServerStream> _connectedClients = new();

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        private void LogToFile(string message)
        {
            try
            {
                var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var logPath = Path.Combine(desktopPath, "mlnet_service_debug.log");
                File.AppendAllText(logPath, $"{DateTime.Now:O} {message}{Environment.NewLine}");
            }
            catch { }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            LogToFile("Service ExecuteAsync starting...");
            _logger.LogInformation("ML.NET Anomaly Detection Service starting at: {time}", DateTimeOffset.Now);

            _captureService = new CaptureService();
            var devices = _captureService.GetDevices();
            LogToFile($"Found {devices.Count} devices.");

            if (devices.Count == 0)
            {
                _logger.LogError("No network devices found. Ensure NPcap is installed.");
                LogToFile("ERROR: No devices found.");
                return;
            }

            // Load settings and try to find last selected device
            var settings = LoadSettings();
            ICaptureDevice? selectedDevice = null;

            if (!string.IsNullOrEmpty(settings.LastSelectedAdapterName))
            {
                selectedDevice = devices.FirstOrDefault(d => d.Name == settings.LastSelectedAdapterName);
                if (selectedDevice != null)
                {
                    LogToFile($"Resuming last selected adapter: {selectedDevice.Name}");
                }
            }

            if (selectedDevice == null)
            {
                // Select the most appropriate interface (active with IPv4, non-loopback, non-virtual)
                selectedDevice = devices.FirstOrDefault(d => 
                    !string.IsNullOrEmpty(d.Description) &&
                    !d.Name.Contains("Loopback") && 
                    !d.Description.Contains("Loopback") &&
                    !d.Description.Contains("WAN Miniport") &&
                    !d.Description.Contains("Virtual") &&
                    (d as SharpPcap.LibPcap.LibPcapLiveDevice)?.Addresses.Any(a => 
                        a.Addr != null && 
                        a.Addr.ipAddress != null && 
                        a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                        !a.Addr.ipAddress.ToString().StartsWith("169.254.") &&
                        a.Addr.ipAddress.ToString() != "0.0.0.0" &&
                        a.Addr.ipAddress.ToString() != "127.0.0.1") == true) 
                    ?? devices.FirstOrDefault(d => !d.Name.Contains("Loopback") && !d.Description.Contains("WAN Miniport")) 
                    ?? devices.First();
                
                LogToFile($"Auto-selected adapter: {selectedDevice.Name}");
            }

            _logger.LogInformation("Selected device: {desc}", selectedDevice.Description);

            _anomalyService = new AnomalyDetectionService();
            _captureService.OnPacketCaptured += _anomalyService.IngestPacket;

            _anomalyService.OnStatsUpdated += (s, ev) =>
            {
                BroadcastMessage(new IPCMessage
                {
                    MessageType = "Stats",
                    PayloadJson = JsonSerializer.Serialize(ev)
                });
            };

            _anomalyService.OnAnomalyDetected += (s, ev) =>
            {
                _logger.LogWarning("Anomaly detected! {reason}", ev.Reason);
                BroadcastMessage(new IPCMessage
                {
                    MessageType = "Anomaly",
                    PayloadJson = JsonSerializer.Serialize(ev)
                });
            };

            _logger.LogInformation("Starting ML.NET pipeline and Capture engine...");
            _anomalyService.Start();
            _captureService.StartCapture(selectedDevice, "");

            _pipeCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            _pipeServerTask = Task.Run(() => StartNamedPipeServer(_pipeCts.Token), _pipeCts.Token);

            _logger.LogInformation("Service is ready and monitoring {desc}.", selectedDevice.Description);

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }

            _pipeCts.Cancel();
            _captureService.StopCapture();
            _anomalyService.Stop();
            
            foreach(var client in _connectedClients.Values)
            {
                try { client.Dispose(); } catch { }
            }
            _connectedClients.Clear();
        }
        
        private async Task StartNamedPipeServer(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    _logger.LogInformation("Starting Named Pipe Server...");
                    LogToFile("Pipe server starting...");

                    var pipeSecurity = new PipeSecurity();
                    pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

                    var pipeServer = NamedPipeServerStreamAcl.Create(
                        "MLNetAnomalyDetectionPipe",
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0, 0, pipeSecurity);

                    LogToFile("Waiting for UI connection...");
                    await pipeServer.WaitForConnectionAsync(token);
                    LogToFile("UI Connected!");
                    
                    var clientId = Guid.NewGuid();
                    _connectedClients.TryAdd(clientId, pipeServer);
                    _logger.LogInformation("UI Client connected! [{clientId}]", clientId);
                    LogToFile($"Client added: {clientId}");

                    // Send current adapter list to client
                    SendAdaptersList(pipeServer);

                    // Clean up disconnected clients and handle incoming commands
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using var reader = new StreamReader(pipeServer);
                            while (pipeServer.IsConnected && !token.IsCancellationRequested)
                            {
                                var line = await reader.ReadLineAsync();
                                if (string.IsNullOrEmpty(line)) break;

                                var msg = JsonSerializer.Deserialize<IPCMessage>(line);
                                if (msg?.MessageType == "SetAdapter")
                                {
                                    _logger.LogInformation("Received SetAdapter command: {payload}", msg.PayloadJson);
                                    HandleSetAdapter(msg.PayloadJson);
                                }
                            }
                        }
                        catch { }
                        finally
                        {
                            _connectedClients.TryRemove(clientId, out _);
                            pipeServer.Dispose();
                            _logger.LogInformation("UI Client disconnected. [{clientId}]", clientId);
                        }
                    });
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error starting Named Pipe Server.");
                    await Task.Delay(2000, token); // Backoff
                }
            }
        }

        private void BroadcastMessage(IPCMessage msg)
        {
            if (_connectedClients.IsEmpty) return;

            var json = JsonSerializer.Serialize(msg) + "\n";
            var bytes = System.Text.Encoding.UTF8.GetBytes(json);

            foreach (var kvp in _connectedClients)
            {
                var pipe = kvp.Value;
                if (!pipe.IsConnected) continue;

                // Fire and forget writing to avoid blocking the high-throughput pcap loop
                Task.Run(async () =>
                {
                    try
                    {
                        await pipe.WriteAsync(bytes, 0, bytes.Length);
                        await pipe.FlushAsync();
                    }
                    catch
                    {
                        // Client likely disconnected
                        pipe.Dispose();
                        _connectedClients.TryRemove(kvp.Key, out _);
                    }
                });
            }
        }

        private void SendAdaptersList(NamedPipeServerStream pipe)
        {
            try
            {
                var devices = SharpPcap.CaptureDeviceList.Instance;
                LogToFile($"SendAdaptersList: Enumerating {devices.Count} devices...");
                var adapters = devices.Select(d => 
                {
                    var pcapDevice = d as SharpPcap.LibPcap.LibPcapLiveDevice;
                    return new NetworkAdapterInfo
                    {
                        Name = d.Name,
                        Description = d.Description,
                        FriendlyName = d.Description.Replace("Network adapter '", "").Replace("' on local host", ""),
                        IpAddress = pcapDevice?.Addresses.FirstOrDefault(a => a.Addr != null && a.Addr.ipAddress != null && a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Addr.ipAddress.ToString() ?? "No IP"
                    };
                }).ToList();

                LogToFile($"SendAdaptersList: Built list with {adapters.Count} items.");
                var json = JsonSerializer.Serialize(new IPCMessage
                {
                    MessageType = "Adapters",
                    PayloadJson = JsonSerializer.Serialize(adapters)
                });

                LogToFile("SendAdaptersList: Writing to pipe...");

                using var writer = new StreamWriter(pipe, leaveOpen: true);
                writer.WriteLine(json);
                writer.Flush();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending adapters list.");
            }
        }

        private void HandleSetAdapter(string deviceName)
        {
            try
            {
                var devices = SharpPcap.CaptureDeviceList.Instance;
                var device = devices.FirstOrDefault(d => d.Name == deviceName);
                if (device != null)
                {
                    _logger.LogInformation("Switching to adapter: {desc}", device.Description);
                    _captureService?.StopCapture();
                    _captureService?.StartCapture(device, "");
                    
                    // Save persistence
                    SaveSettings(new AppSettings { LastSelectedAdapterName = deviceName });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error switching adapter.");
            }
        }

        private AppSettings LoadSettings()
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MLNetAnomalyDetection");
                var path = Path.Combine(dir, "settings.json");
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch (Exception ex) { LogToFile($"Error loading settings: {ex.Message}"); }
            return new AppSettings();
        }

        private void SaveSettings(AppSettings settings)
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MLNetAnomalyDetection");
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, "settings.json");
                var json = JsonSerializer.Serialize(settings);
                File.WriteAllText(path, json);
            }
            catch (Exception ex) { LogToFile($"Error saving settings: {ex.Message}"); }
        }
    }
}
