using System;

namespace Sharphound.Proxy
{
    public sealed class Socks5ProxyConfig
    {
        public string ProxyHost { get; }
        public int ProxyPort { get; }
        public string Username { get; }
        public string Password { get; }
        public bool RequiresAuthentication => Username != null;

        public Socks5ProxyConfig(string proxyHost, int proxyPort, string username = null, string password = null)
        {
            ProxyHost = proxyHost;
            ProxyPort = proxyPort;
            Username = username;
            Password = password;
        }

        /// <summary>
        /// Parses a proxy string in format "socks5://host:port" or "host:port".
        /// Returns null if the input is null or empty.
        /// Throws ArgumentException if the format is invalid.
        /// </summary>
        public static Socks5ProxyConfig Parse(string proxyString, string username = null, string password = null)
        {
            if (string.IsNullOrWhiteSpace(proxyString))
                return null;

            var cleaned = proxyString.Trim();
            if (cleaned.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
                cleaned = cleaned.Substring("socks5://".Length);

            var parts = cleaned.Split(':');
            if (parts.Length != 2 || !int.TryParse(parts[1], out var port) || port <= 0 || port > 65535)
                throw new ArgumentException(
                    $"Invalid proxy format: '{proxyString}'. Expected 'socks5://host:port' or 'host:port'.");

            return new Socks5ProxyConfig(parts[0], port, username, password);
        }
    }
}
