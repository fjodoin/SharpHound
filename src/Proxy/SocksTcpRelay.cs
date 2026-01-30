using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sharphound.Proxy
{
    /// <summary>
    /// TCP relay that listens locally and tunnels each connection through SOCKS5 to a fixed target.
    /// Supports concurrent connections for LDAP connection pooling.
    /// </summary>
    public sealed class SocksTcpRelay : IDisposable
    {
        private readonly Socks5ProxyConfig _proxyConfig;
        private readonly string _targetHost;
        private readonly int _targetPort;
        private readonly ILogger _logger;
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts;
        private Task _acceptLoopTask;
        private bool _disposed;

        /// <summary>
        /// The local port this relay is listening on. Available after Start().
        /// </summary>
        public int LocalPort { get; private set; }

        public SocksTcpRelay(
            Socks5ProxyConfig proxyConfig,
            string targetHost,
            int targetPort,
            ILogger logger,
            CancellationToken externalCancellation)
        {
            _proxyConfig = proxyConfig;
            _targetHost = targetHost;
            _targetPort = targetPort;
            _logger = logger;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancellation);
        }

        public void Start()
        {
            _listener.Start();
            LocalPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _logger.LogInformation(
                "SOCKS5 relay listening on 127.0.0.1:{LocalPort} -> {Target}:{TargetPort} via {Proxy}:{ProxyPort}",
                LocalPort, _targetHost, _targetPort, _proxyConfig.ProxyHost, _proxyConfig.ProxyPort);
            _acceptLoopTask = AcceptLoopAsync();
        }

        private async Task AcceptLoopAsync()
        {
            try
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    TcpClient localClient;
                    try
                    {
                        localClient = await _listener.AcceptTcpClientAsync();
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (SocketException) when (_cts.Token.IsCancellationRequested)
                    {
                        break;
                    }

                    _ = HandleConnectionAsync(localClient);
                }
            }
            catch (Exception ex) when (!_cts.Token.IsCancellationRequested)
            {
                _logger.LogError(ex, "SOCKS5 relay accept loop error");
            }
        }

        private async Task HandleConnectionAsync(TcpClient localClient)
        {
            TcpClient proxyClient = null;
            try
            {
                _logger.LogTrace("New relay connection, opening SOCKS5 tunnel to {Host}:{Port}",
                    _targetHost, _targetPort);

                proxyClient = await Socks5Client.ConnectAsync(
                    _proxyConfig, _targetHost, _targetPort, _cts.Token);

                var localStream = localClient.GetStream();
                var proxyStream = proxyClient.GetStream();

                var localToProxy = RelayAsync(localStream, proxyStream, _cts.Token);
                var proxyToLocal = RelayAsync(proxyStream, localStream, _cts.Token);

                await Task.WhenAny(localToProxy, proxyToLocal);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SOCKS5 relay connection error");
            }
            finally
            {
                SafeClose(localClient);
                SafeClose(proxyClient);
            }
        }

        private static async Task RelayAsync(NetworkStream source, NetworkStream destination, CancellationToken ct)
        {
            var buffer = new byte[8192];
            try
            {
                while (true)
                {
                    var bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, ct);
                    if (bytesRead == 0) break;
                    await destination.WriteAsync(buffer, 0, bytesRead, ct);
                    await destination.FlushAsync(ct);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (OperationCanceledException) { }
        }

        private static void SafeClose(TcpClient client)
        {
            try { client?.Close(); }
            catch { /* swallow */ }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cts.Cancel();
            try { _listener.Stop(); }
            catch { /* swallow */ }
            _cts.Dispose();
        }
    }
}
