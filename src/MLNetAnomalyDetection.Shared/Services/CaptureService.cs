using System;
using System.Collections.Generic;
using System.Linq;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using MLNetAnomalyDetection.Models;

namespace MLNetAnomalyDetection.Services
{
    public class CaptureService
    {
        private ICaptureDevice? _currentDevice;
        private ICaptureDevice? _fileDevice;
        private int _packetCount;
        
        // Cache raw packets to support saving them later
        private readonly List<RawCapture> _rawPackets = new List<RawCapture>();

        public event EventHandler<PacketModel>? OnPacketCaptured;
        public Action? OnFileCaptureComplete;
        public event EventHandler<string>? OnCaptureError;

        public List<ICaptureDevice> GetDevices()
        {
            var captureDeviceList = CaptureDeviceList.Instance;
            return captureDeviceList.Cast<ICaptureDevice>().ToList();
        }

        public void StartCapture(ICaptureDevice device, string filterExp)
        {
            if (_currentDevice != null && _currentDevice.Started)
            {
                StopCapture();
            }

            try
            {
                _currentDevice = device;
                _packetCount = 0;
                _rawPackets.Clear();

                _currentDevice.OnPacketArrival += Device_OnPacketArrival;
                
                // Open the device for capturing
                int readTimeoutMilliseconds = 1000;
                _currentDevice.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

                // Set filter if provided
                if (!string.IsNullOrWhiteSpace(filterExp))
                {
                    _currentDevice.Filter = filterExp;
                }

                _currentDevice.StartCapture();
            }
            catch (Exception ex)
            {
                OnCaptureError?.Invoke(this, $"Error starting capture: {ex.Message}");
            }
        }

        public void StopCapture()
        {
            if (_currentDevice != null)
            {
                try
                {
                    if (_currentDevice.Started)
                    {
                        _currentDevice.StopCapture();
                    }
                }
                catch (Exception)
                {
                    // Ignore stopping errors
                }
                finally
                {
                    _currentDevice.OnPacketArrival -= Device_OnPacketArrival;
                    _currentDevice.Close();
                    _currentDevice = null;
                }
            }

            if (_fileDevice != null)
            {
                 try
                {
                    _fileDevice.StopCapture();
                }
                catch { }
                finally
                {
                    _fileDevice.OnPacketArrival -= Device_OnPacketArrival;
                    _fileDevice.OnCaptureStopped -= FileDevice_OnCaptureStopped;
                    _fileDevice.Close();
                    _fileDevice = null;
                }
            }
        }

        public void LoadFromPcap(string filePath)
        {
            StopCapture();

            try
            {
                _packetCount = 0;
                _rawPackets.Clear();

                _fileDevice = new CaptureFileReaderDevice(filePath);
                _fileDevice.OnPacketArrival += Device_OnPacketArrival;
                _fileDevice.OnCaptureStopped += FileDevice_OnCaptureStopped;
                
                _fileDevice.Open();
                
                // Read in background so we don't block
                System.Threading.Tasks.Task.Run(() => 
                {
                    try
                    {
                        _fileDevice.Capture();
                    }
                    catch (Exception ex)
                    {
                        OnCaptureError?.Invoke(this, $"Error reading PCAP: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                OnCaptureError?.Invoke(this, $"Error opening PCAP file: {ex.Message}");
            }
        }

        private void FileDevice_OnCaptureStopped(object sender, CaptureStoppedEventStatus status)
        {
            OnFileCaptureComplete?.Invoke();
        }

        public void SaveToPcap(string filePath)
        {
            if (_rawPackets.Count == 0) return;

            try
            {
                // Create a writer device based on the first packet's link type
                using var writer = new CaptureFileWriterDevice(filePath);
                writer.Open();

                foreach (var rawPacket in _rawPackets)
                {
                    writer.Write(rawPacket);
                }
            }
            catch (Exception ex)
            {
                OnCaptureError?.Invoke(this, $"Error saving PCAP file: {ex.Message}");
            }
        }

        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            _packetCount++;
            var rawPacket = e.GetPacket();
            
            // Critical for saving
            lock (_rawPackets)
            {
                _rawPackets.Add(rawPacket);
            }

            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            if (packet != null)
            {
                var model = new PacketModel
                {
                    Number = _packetCount,
                    Time = e.Header.Timeval.Date,
                    Length = e.GetPacket().Data.Length
                };

                // Try to get IP info
                var ipPacket = packet.Extract<IPPacket>();
                if (ipPacket != null)
                {
                    model.SourceIp = ipPacket.SourceAddress.ToString();
                    model.DestinationIp = ipPacket.DestinationAddress.ToString();
                    model.Protocol = ipPacket.Protocol.ToString();
                    
                    var tcpPacket = packet.Extract<TcpPacket>();
                    if (tcpPacket != null)
                    {
                         model.SourcePort = tcpPacket.SourcePort;
                         model.DestinationPort = tcpPacket.DestinationPort;
                         model.Info = $"{tcpPacket.SourcePort} -> {tcpPacket.DestinationPort} Seq={tcpPacket.SequenceNumber}";
                         model.Payload = tcpPacket.PayloadData;
                         model.TcpSequenceNumber = tcpPacket.SequenceNumber;

                         if ((model.SourcePort == 80 || model.DestinationPort == 80) && model.Payload != null && model.Payload.Length > 0)
                         {
                             var payloadStr = System.Text.Encoding.ASCII.GetString(model.Payload);
                             if (payloadStr.StartsWith("GET ") || payloadStr.StartsWith("POST ") || payloadStr.StartsWith("HTTP/"))
                             {
                                 model.Protocol = "HTTP";
                                 var firstLine = payloadStr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                                 if (!string.IsNullOrEmpty(firstLine)) model.Info = firstLine;
                             }
                         }
                         else if ((model.SourcePort == 443 || model.DestinationPort == 443) && model.Payload != null && model.Payload.Length > 5)
                         {
                             // It's on a TLS port and has at least a TLS record header length
                             model.Protocol = "TLS";
                             
                             // Attempt to extract SNI (Server Name Indication) from TLS Client Hello
                             var sni = ExtractTlsSni(model.Payload);
                             if (!string.IsNullOrEmpty(sni))
                             {
                                 model.Info = $"Client Hello (SNI: {sni})";
                             }
                             else
                             {
                                 // Check if it's a Server Hello or other handshake
                                 if (model.Payload[0] == 22 && model.Payload.Length > 9)
                                 {
                                     if (model.Payload[5] == 2) model.Info = "Server Hello";
                                     else model.Info = "TLS Handshake";
                                 }
                                 else if (model.Payload[0] == 23)
                                 {
                                     model.Info = "Application Data";
                                 }
                                 else 
                                 {
                                     model.Info = "TLS Record";
                                 }
                             }
                         }
                    }
                    else
                    {
                        var udpPacket = packet.Extract<UdpPacket>();
                        if (udpPacket != null)
                        {
                            model.SourcePort = udpPacket.SourcePort;
                            model.DestinationPort = udpPacket.DestinationPort;
                            model.Info = $"{udpPacket.SourcePort} -> {udpPacket.DestinationPort} Len={udpPacket.Length}";
                            model.Payload = udpPacket.PayloadData;

                            if ((model.SourcePort == 53 || model.DestinationPort == 53) && model.Payload != null && model.Payload.Length > 12)
                            {
                                model.Protocol = "DNS";
                                var queryName = ExtractSimpleDnsName(model.Payload);
                                if (!string.IsNullOrEmpty(queryName))
                                {
                                    bool isResponse = (model.SourcePort == 53);
                                    model.Info = $"{(isResponse ? "Response" : "Query")} {queryName}";
                                }
                            }
                        }
                    }
                }
                else
                {
                    // Non-IP packet (e.g., ARP)
                    var arpPacket = packet.Extract<ArpPacket>();
                    if (arpPacket != null)
                    {
                        model.Protocol = "ARP";
                        model.Info = $"Who has {arpPacket.TargetProtocolAddress}? Tell {arpPacket.SenderProtocolAddress}";
                    }
                    else
                    {
                        model.Protocol = "Unknown";
                        model.Info = "Non-IP Packet";
                    }
                }

                OnPacketCaptured?.Invoke(this, model);
            }
        }

        private string ExtractSimpleDnsName(byte[] payload)
        {
            try
            {
                // Simple parsing for standard DNS query format right after 12 byte header
                var sb = new System.Text.StringBuilder();
                int idx = 12; // Start of questions section
                while (idx < payload.Length)
                {
                    int len = payload[idx];
                    if (len == 0) break; // Null terminator
                    if ((len & 0xC0) == 0xC0) break; // Pointer (compression), ignore for simple parsing
                    
                    idx++;
                    if (idx + len > payload.Length) break;

                    if (sb.Length > 0) sb.Append(".");
                    sb.Append(System.Text.Encoding.ASCII.GetString(payload, idx, len));
                    idx += len;
                }
                return sb.ToString();
            }
            catch
            {
                return string.Empty;
            }
        }

        private string ExtractTlsSni(byte[] payload)
        {
            try
            {
                // TLS Record header:
                // byte 0: Content Type (22 = Handshake)
                // bytes 1-2: Version (e.g., 03 01 for TLS 1.0)
                // bytes 3-4: Length
                if (payload[0] != 22) return string.Empty; 

                // Handshake header:
                // byte 5: Handshake Type (1 = Client Hello)
                // bytes 6-8: Length
                if (payload[5] != 1) return string.Empty;

                int pos = 9; // Start of Client Hello

                // Version (2 bytes)
                pos += 2;
                
                // Random (32 bytes)
                pos += 32;

                if (pos >= payload.Length) return string.Empty;
                
                // Session ID details
                int sessionidLen = payload[pos];
                pos += 1 + sessionidLen;

                if (pos >= payload.Length - 2) return string.Empty;

                // Cipher Suites length (2 bytes)
                int cipherSuitesLen = (payload[pos] << 8) | payload[pos + 1];
                pos += 2 + cipherSuitesLen;

                if (pos >= payload.Length - 1) return string.Empty;

                // Compression Methods length (1 byte)
                int compressMethodsLen = payload[pos];
                pos += 1 + compressMethodsLen;

                if (pos >= payload.Length - 2) return string.Empty;

                // Extensions Length (2 bytes)
                int extensionsLen = (payload[pos] << 8) | payload[pos + 1];
                pos += 2;

                int extensionsEnd = pos + extensionsLen;

                while (pos < extensionsEnd && pos < payload.Length - 4)
                {
                    int extensionType = (payload[pos] << 8) | payload[pos + 1];
                    int extensionLen = (payload[pos + 2] << 8) | payload[pos + 3];
                    pos += 4;

                    if (extensionType == 0) // Server Name (SNI)
                    {
                        if (pos >= payload.Length - 2) break;
                        // Server Name list length
                        pos += 2;

                        if (pos >= payload.Length - 1) break;
                        // Server Name Type (0 = host_name)
                        if (payload[pos] == 0)
                        {
                            pos += 1;
                            if (pos >= payload.Length - 2) break;
                            
                            // Host Name Length
                            int nameLen = (payload[pos] << 8) | payload[pos + 1];
                            pos += 2;

                            if (pos + nameLen <= payload.Length)
                            {
                                return System.Text.Encoding.ASCII.GetString(payload, pos, nameLen);
                            }
                        }
                        break;
                    }
                    else
                    {
                        pos += extensionLen; // Skip other extensions
                    }
                }

                return string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
