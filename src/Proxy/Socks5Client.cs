using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sharphound.Proxy
{
    /// <summary>
    /// Creates TCP connections through a SOCKS5 proxy.
    /// Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password auth).
    /// </summary>
    public static class Socks5Client
    {
        private const byte SocksVersion = 0x05;
        private const byte AuthNone = 0x00;
        private const byte AuthUsernamePassword = 0x02;
        private const byte AuthNoAcceptable = 0xFF;
        private const byte CmdConnect = 0x01;
        private const byte AddrTypeDomainName = 0x03;
        private const byte AddrTypeIPv4 = 0x01;
        private const byte ReplySuccess = 0x00;

        /// <summary>
        /// Connect to targetHost:targetPort through the SOCKS5 proxy.
        /// Returns a connected TcpClient whose NetworkStream is ready for use.
        /// </summary>
        public static async Task<TcpClient> ConnectAsync(
            Socks5ProxyConfig config,
            string targetHost,
            int targetPort,
            CancellationToken cancellationToken = default,
            int connectTimeoutMs = 10000)
        {
            var client = new TcpClient();
            try
            {
                // Step 1: Connect to the SOCKS5 proxy
                var connectTask = client.ConnectAsync(config.ProxyHost, config.ProxyPort);
                var timeoutTask = Task.Delay(connectTimeoutMs, cancellationToken);
                if (await Task.WhenAny(connectTask, timeoutTask) != connectTask)
                {
                    client.Close();
                    throw new TimeoutException(
                        $"Timed out connecting to SOCKS5 proxy at {config.ProxyHost}:{config.ProxyPort}");
                }

                await connectTask; // propagate any exception
                var stream = client.GetStream();

                // Step 2: Send greeting (method negotiation)
                byte[] greeting;
                if (config.RequiresAuthentication)
                    greeting = new byte[] { SocksVersion, 0x02, AuthNone, AuthUsernamePassword };
                else
                    greeting = new byte[] { SocksVersion, 0x01, AuthNone };

                await stream.WriteAsync(greeting, 0, greeting.Length, cancellationToken);

                var greetingResponse = new byte[2];
                await ReadExactAsync(stream, greetingResponse, cancellationToken);

                if (greetingResponse[0] != SocksVersion)
                    throw new ProtocolViolationException("SOCKS5 proxy returned invalid version");
                if (greetingResponse[1] == AuthNoAcceptable)
                    throw new ProtocolViolationException(
                        "SOCKS5 proxy rejected all authentication methods");

                // Step 3: Handle username/password auth if selected
                if (greetingResponse[1] == AuthUsernamePassword)
                {
                    if (!config.RequiresAuthentication)
                        throw new InvalidOperationException(
                            "SOCKS5 proxy requires authentication but no credentials were provided");

                    var usernameBytes = Encoding.ASCII.GetBytes(config.Username);
                    var passwordBytes = Encoding.ASCII.GetBytes(config.Password);
                    var authRequest = new byte[3 + usernameBytes.Length + passwordBytes.Length];
                    authRequest[0] = 0x01; // auth sub-negotiation version
                    authRequest[1] = (byte)usernameBytes.Length;
                    Buffer.BlockCopy(usernameBytes, 0, authRequest, 2, usernameBytes.Length);
                    authRequest[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
                    Buffer.BlockCopy(passwordBytes, 0, authRequest, 3 + usernameBytes.Length, passwordBytes.Length);

                    await stream.WriteAsync(authRequest, 0, authRequest.Length, cancellationToken);

                    var authResponse = new byte[2];
                    await ReadExactAsync(stream, authResponse, cancellationToken);
                    if (authResponse[1] != 0x00)
                        throw new InvalidOperationException(
                            $"SOCKS5 proxy authentication failed (status=0x{authResponse[1]:X2})");
                }

                // Step 4: Send CONNECT request
                byte[] connectRequest;
                if (IPAddress.TryParse(targetHost, out var ip))
                {
                    var ipBytes = ip.GetAddressBytes();
                    connectRequest = new byte[4 + 4 + 2];
                    connectRequest[0] = SocksVersion;
                    connectRequest[1] = CmdConnect;
                    connectRequest[2] = 0x00; // reserved
                    connectRequest[3] = AddrTypeIPv4;
                    Buffer.BlockCopy(ipBytes, 0, connectRequest, 4, 4);
                    connectRequest[8] = (byte)(targetPort >> 8);
                    connectRequest[9] = (byte)(targetPort & 0xFF);
                }
                else
                {
                    var hostBytes = Encoding.ASCII.GetBytes(targetHost);
                    connectRequest = new byte[4 + 1 + hostBytes.Length + 2];
                    connectRequest[0] = SocksVersion;
                    connectRequest[1] = CmdConnect;
                    connectRequest[2] = 0x00;
                    connectRequest[3] = AddrTypeDomainName;
                    connectRequest[4] = (byte)hostBytes.Length;
                    Buffer.BlockCopy(hostBytes, 0, connectRequest, 5, hostBytes.Length);
                    connectRequest[5 + hostBytes.Length] = (byte)(targetPort >> 8);
                    connectRequest[6 + hostBytes.Length] = (byte)(targetPort & 0xFF);
                }

                await stream.WriteAsync(connectRequest, 0, connectRequest.Length, cancellationToken);

                // Step 5: Read CONNECT response
                var responseHeader = new byte[4];
                await ReadExactAsync(stream, responseHeader, cancellationToken);

                if (responseHeader[0] != SocksVersion)
                    throw new ProtocolViolationException("Invalid SOCKS5 response version");
                if (responseHeader[1] != ReplySuccess)
                    throw new Socks5Exception(responseHeader[1]);

                // Consume bound address based on ATYP
                switch (responseHeader[3])
                {
                    case 0x01: // IPv4: 4 bytes + 2 port
                        await ReadExactAsync(stream, new byte[6], cancellationToken);
                        break;
                    case 0x03: // Domain: 1 len + N + 2 port
                        var lenBuf = new byte[1];
                        await ReadExactAsync(stream, lenBuf, cancellationToken);
                        await ReadExactAsync(stream, new byte[lenBuf[0] + 2], cancellationToken);
                        break;
                    case 0x04: // IPv6: 16 bytes + 2 port
                        await ReadExactAsync(stream, new byte[18], cancellationToken);
                        break;
                }

                return client;
            }
            catch
            {
                client?.Close();
                throw;
            }
        }

        private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer, offset, buffer.Length - offset, ct);
                if (read == 0)
                    throw new IOException("SOCKS5 proxy closed connection unexpectedly");
                offset += read;
            }
        }
    }

    public class Socks5Exception : Exception
    {
        public byte ReplyCode { get; }

        public Socks5Exception(byte replyCode)
            : base($"SOCKS5 CONNECT failed (0x{replyCode:X2}): {GetMessage(replyCode)}")
        {
            ReplyCode = replyCode;
        }

        private static string GetMessage(byte code)
        {
            switch (code)
            {
                case 0x01: return "General SOCKS server failure";
                case 0x02: return "Connection not allowed by ruleset";
                case 0x03: return "Network unreachable";
                case 0x04: return "Host unreachable";
                case 0x05: return "Connection refused";
                case 0x06: return "TTL expired";
                case 0x07: return "Command not supported";
                case 0x08: return "Address type not supported";
                default: return "Unknown error";
            }
        }
    }
}
