// ---------------------------------------------------- //
//    ______                 __ __                  __  //
//   / __/ /  ___ ________  / // /_   __ _____  ___/ /  //
//  _\ \/ _ \/ _ `/ __/ _ \/ _  / _ \/ // / _ \/ _  /   //
// /___/_//_/\_,_/_/ / .__/_//_/\___/\_,_/_//_/\_,_/    //
//                  /_/                                 //
//  app type    : console                               //
//  dotnet ver. : 462                                   //
//  client ver  : 3?                                    //
//  license     : open....?                             //
//------------------------------------------------------//
// creational_pattern : Inherit from System.CommandLine //
// structural_pattern  : Chain Of Responsibility         //
// behavioral_pattern : inherit from SharpHound3        //
// ---------------------------------------------------- //

using System;
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Sharphound.Client;
using Sharphound.Proxy;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace Sharphound
{

    #region Reference Implementations

    #endregion

    #region Console Entrypoint

    public class Program {
        public static async Task Main(string[] args) {
            var logger = new BasicLogger((int)LogLevel.Information);
            logger.LogInformation("This version of SharpHound is compatible with the 5.0.0 Release of BloodHound");

            try {
                logger.LogInformation("SharpHound Version: {Version}", Assembly.GetExecutingAssembly().GetName().Version);
                logger.LogInformation("SharpHound Common Version: {Version}", Assembly.GetAssembly(typeof(CommonLib)).GetName().Version);
                // Checks the release version available on the machine.
                var releaseVersion = (int) Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Release", 0);
                if (releaseVersion == 0) releaseVersion = (int) Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Release", 0);
                // The value 461808 corresponds to .Net 4.7.2
                if (releaseVersion < 461808)
                {
                    logger.LogError("The .Net Runtime is not compatible with SharpHound. Please update to .Net 4.7.2.");
                    return;
                }

                var parser = new Parser(with => {
                    with.CaseInsensitiveEnumValues = true;
                    with.CaseSensitive = false;
                    with.HelpWriter = Console.Error;
                });
                var options = parser.ParseArguments<Options>(args);

                await options.WithParsedAsync(async options =>
                {
                    if (!options.ResolveCollectionMethods(logger, out var resolved, out var dconly)) return;

                    logger = new BasicLogger(options.Verbosity);

                    var flags = new Flags
                    {
                        Loop = options.Loop,
                        DumpComputerStatus = options.TrackComputerCalls,
                        NoRegistryLoggedOn = options.SkipRegistryLoggedOn,
                        ExcludeDomainControllers = options.ExcludeDCs,
                        SkipPortScan = options.SkipPortCheck,
                        SkipPasswordAgeCheck = options.SkipPasswordCheck,
                        DisableKerberosSigning = options.DisableSigning,
                        SecureLDAP = options.ForceSecureLDAP,
                        InvalidateCache = options.RebuildCache,
                        NoZip = options.NoZip,
                        NoOutput = false,
                        Stealth = options.Stealth,
                        RandomizeFilenames = options.RandomFileNames,
                        MemCache = options.MemCache,
                        CollectAllProperties = options.CollectAllProperties,
                        DCOnly = dconly,
                        PrettyPrint = options.PrettyPrint,
                        SearchForest = options.SearchForest,
                        RecurseDomains = options.RecurseDomains,
                        DoLocalAdminSessionEnum = options.DoLocalAdminSessionEnum,
                        ParititonLdapQueries = options.PartitionLdapQueries
                    };

                    var ldapOptions = new LdapConfig
                    {
                        Port = options.LDAPPort,
                        SSLPort = options.LDAPSSLPort,
                        DisableSigning = options.DisableSigning,
                        ForceSSL = options.ForceSecureLDAP,
                        AuthType = AuthType.Negotiate,
                        DisableCertVerification = options.DisableCertVerification
                    };

                    if (options.DomainController != null) ldapOptions.Server = options.DomainController;

                    if (options.LDAPUsername != null)
                    {
                        if (options.LDAPPassword == null)
                        {
                            logger.LogError("You must specify LDAPPassword if using the LDAPUsername options");
                            return;
                        }

                        ldapOptions.Username = options.LDAPUsername;
                        ldapOptions.Password = options.LDAPPassword;
                    }

                    // SOCKS5 Proxy validation
                    Socks5ProxyConfig proxyConfig = null;
                    if (options.Proxy != null)
                    {
                        try
                        {
                            proxyConfig = Socks5ProxyConfig.Parse(
                                options.Proxy, options.ProxyUsername, options.ProxyPassword);
                        }
                        catch (ArgumentException ex)
                        {
                            logger.LogError("Invalid proxy configuration: {Message}", ex.Message);
                            return;
                        }

                        if ((options.ProxyUsername != null) != (options.ProxyPassword != null))
                        {
                            logger.LogError(
                                "You must specify both --proxyusername and --proxypassword for SOCKS5 proxy authentication");
                            return;
                        }

                        if (options.DomainController == null)
                        {
                            logger.LogError(
                                "You must specify --domaincontroller when using --proxy (DNS resolution may not work through the proxy)");
                            return;
                        }

                        if (options.LDAPUsername == null || options.LDAPPassword == null)
                        {
                            logger.LogError(
                                "You must specify --ldapusername and --ldappassword when using --proxy (Kerberos cannot authenticate to the local relay)");
                            return;
                        }

                        if (flags.SearchForest || flags.RecurseDomains)
                        {
                            logger.LogWarning(
                                "Cross-domain enumeration with SOCKS5 proxy may not work correctly. " +
                                "The LDAP relay only tunnels to the DC specified by --domaincontroller. " +
                                "Consider running SharpHound separately for each domain.");
                        }

                        logger.LogWarning(
                            "SOCKS5 proxy enabled. RPC/SMB-based collection methods (Session, LocalGroup, " +
                            "UserRights, Registry, etc.) will NOT be tunneled. Use --collectionmethods DCOnly " +
                            "for full proxy coverage, or use an external tool (e.g., Proxifier) for RPC/SMB.");
                    }

                    // Check to make sure both Local Admin Session Enum options are set if either is set

                    if (options.LocalAdminPassword != null && options.LocalAdminUsername == null ||
                        options.LocalAdminUsername != null && options.LocalAdminPassword == null)
                    {
                        logger.LogError(
                            "You must specify both LocalAdminUsername and LocalAdminPassword if using these options!");
                        return;
                    }

                    // Check to make sure doLocalAdminSessionEnum is set when specifying localadmin and password

                    if (options.LocalAdminPassword != null || options.LocalAdminUsername != null)
                    {
                        if (options.DoLocalAdminSessionEnum == false)
                        {
                            logger.LogError(
                                "You must use the --doLocalAdminSessionEnum switch in combination with --LocalAdminUsername and --LocalAdminPassword!");
                            return;
                        }
                    }

                    // Check to make sure LocalAdminUsername and LocalAdminPassword are set when using doLocalAdminSessionEnum

                    if (options.DoLocalAdminSessionEnum == true)
                    {
                        if (options.LocalAdminPassword == null || options.LocalAdminUsername == null)
                        {
                            logger.LogError(
                                "You must specify both LocalAdminUsername and LocalAdminPassword if using the --doLocalAdminSessionEnum option!");
                            return;
                        }
                    }

                    await StartCollection(options, logger, resolved, flags, ldapOptions, proxyConfig);
                });
            } catch (Exception ex) {
                logger.LogError($"Error running SharpHound: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static async Task StartCollection(Options options, BasicLogger logger, CollectionMethod resolved, Flags flags, LdapConfig ldapOptions, Socks5ProxyConfig proxyConfig)
        {
            SocksTcpRelay ldapRelay = null;
            SocksTcpRelay ldapsRelay = null;

            try
            {
                // Set up SOCKS5 relays if proxy is configured
                if (proxyConfig != null)
                {
                    var targetDC = ldapOptions.Server;

                    // Test SOCKS5 connectivity before proceeding
                    var ldapPort = ldapOptions.Port > 0 ? ldapOptions.Port : 389;
                    logger.LogInformation("Testing SOCKS5 proxy connectivity to {DC}:{Port}...", targetDC, ldapPort);
                    try
                    {
                        using (var testClient = await Socks5Client.ConnectAsync(
                            proxyConfig, targetDC, ldapPort, CancellationToken.None, 15000))
                        {
                            logger.LogInformation("SOCKS5 proxy connectivity test succeeded");
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError("SOCKS5 proxy connectivity test failed: {Message}", ex.Message);
                        logger.LogError("Cannot reach {DC}:{Port} through proxy {Proxy}:{ProxyPort}",
                            targetDC, ldapPort, proxyConfig.ProxyHost, proxyConfig.ProxyPort);
                        return;
                    }

                    // Start LDAP relay
                    ldapRelay = new SocksTcpRelay(proxyConfig, targetDC, ldapPort, logger, CancellationToken.None);
                    ldapRelay.Start();

                    // Start LDAPS relay
                    var ldapsPort = ldapOptions.SSLPort > 0 ? ldapOptions.SSLPort : 636;
                    ldapsRelay = new SocksTcpRelay(proxyConfig, targetDC, ldapsPort, logger, CancellationToken.None);
                    ldapsRelay.Start();

                    // Override LDAP config to point at local relays
                    ldapOptions.Server = "127.0.0.1";
                    ldapOptions.Port = ldapRelay.LocalPort;
                    ldapOptions.SSLPort = ldapsRelay.LocalPort;

                    // Kerberos cannot authenticate against 127.0.0.1, force Basic auth
                    ldapOptions.AuthType = AuthType.Basic;
                    ldapOptions.DisableSigning = true;

                    if (!ldapOptions.ForceSSL)
                    {
                        logger.LogWarning(
                            "Using Basic auth without LDAPS. Credentials are sent in cleartext to the relay. " +
                            "Consider adding --forcesecureldap for encrypted LDAP.");
                    }
                }

                IContext context = new BaseContext(logger, ldapOptions, flags)
                {
                    DomainName = options.Domain,
                    CacheFileName = options.CacheName,
                    ZipFilename = options.ZipFilename,
                    SearchBase = options.DistinguishedName,
                    StatusInterval = options.StatusInterval,
                    RealDNSName = options.RealDNSName,
                    ComputerFile = options.ComputerFile,
                    OutputPrefix = options.OutputPrefix,
                    OutputDirectory = options.OutputDirectory,
                    Jitter = options.Jitter,
                    Throttle = options.Throttle,
                    LdapFilter = options.LdapFilter,
                    PortScanTimeout = options.PortCheckTimeout,
                    ResolvedCollectionMethods = resolved,
                    Threads = options.Threads,
                    LoopDuration = options.LoopDuration,
                    LoopInterval = options.LoopInterval,
                    ZipPassword = options.ZipPassword,
                    IsFaulted = false,
                    IsProxyEnabled = proxyConfig != null,
                    LocalAdminUsername = options.LocalAdminUsername,
                    LocalAdminPassword = options.LocalAdminPassword
                };

                var cancellationTokenSource = new CancellationTokenSource();
                context.CancellationTokenSource = cancellationTokenSource;

                // Create new chain links
                Links<IContext> links = new SharpLinks();

                // Run our chain
                context = links.Initialize(context, ldapOptions);
                if (context.Flags.IsFaulted)
                    return;
                context = await links.TestConnection(context);
                if (context.Flags.IsFaulted)
                    return;
                context = links.SetSessionUserName(options.OverrideUserName, context);
                context = links.InitCommonLib(context);
                context = await links.GetDomainsForEnumeration(context);
                if (context.Flags.IsFaulted)
                    return;
                context = links.StartBaseCollectionTask(context);
                context = await links.AwaitBaseRunCompletion(context);
                context = links.StartLoopTimer(context);
                context = links.StartLoop(context);
                context = await links.AwaitLoopCompletion(context);
                context = links.SaveCacheFile(context);
                links.Finish(context);
            }
            finally
            {
                ldapRelay?.Dispose();
                ldapsRelay?.Dispose();
            }
        }

        // Accessor function for the PS1 to work, do not change or remove
        public static void InvokeSharpHound(string[] args) {
            Main(args).Wait();
        }
    }

    #endregion
}