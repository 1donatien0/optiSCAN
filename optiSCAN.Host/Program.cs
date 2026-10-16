// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using optiSCAN.Localization;
using optiSCAN.Services;

namespace optiSCAN.Host;

/// <summary>
/// Hôte de la protection système. Deux modes seulement :
/// <list type="bullet">
/// <item><c>--service-host</c> : lancé par le service <c>optiSCANProtection</c> sous SYSTEM ;</item>
/// <item><c>--clamd-relay</c> : relais de clamd, lancé dans son AppContainer par l'hôte.</item>
/// </list>
/// Avant 3.1, ces modes vivaient dans l'exécutable WPF (vingt modes, une seule image chargée sous
/// SYSTEM). Tout autre argument est refusé.
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var mode = HeadlessScanArguments.ParseMode(args);

#if OPTISCAN_TEST_HOOKS
        // Faux clamd des tests d'isolation : absent du binaire publié.
        if (mode == HeadlessScanArguments.Mode.ClamdStub)
        {
            if (string.Equals(Environment.GetEnvironmentVariable("OPTISCAN_CLAMD_STUB"), "1", StringComparison.Ordinal)
                && HeadlessScanArguments.TryParseClamdStub(args, out var stubPort))
            {
                try { ClamdLoopbackStub.Run(stubPort); }
                catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or ObjectDisposedException) { /* arrêté */ }
            }
            return 0;
        }
#endif

        if (mode == HeadlessScanArguments.Mode.ClamdRelay)
        {
            // Relais lancé dans l'AppContainer de clamd : aucun autre service n'est créé.
            if (HeadlessScanArguments.TryParseClamdRelay(args, out var relayPort, out var relayParent, out var relayFile))
            {
                try { ClamdRelay.Run(relayPort, relayParent, relayFile); }
                catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or ObjectDisposedException or InvalidOperationException) { /* arrêté */ }
            }
            return 0;
        }

        if (mode != HeadlessScanArguments.Mode.ServiceHost)
        {
            AppLogger.Warn("Host", "Argument refusé : optiSCAN.Host n'accepte que --service-host et --clamd-relay");
            return 2;
        }

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex)
                AppLogger.Error("Host", "Exception non gérée", ex);
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            AppLogger.Error("Host", "Tâche non observée", e.Exception);
            e.SetObserved();
        };

        if (!IsSystem())
        {
            AppLogger.Warn("Host", "Refus de --service-host : réservé au service Windows");
            return 3;
        }

        if (!optiSCAN.Platform.InstallLocationTrust.IsCurrentInstallTrusted(out var installReason))
        {
            AppLogger.Warn("Host", "Hôte de service refusé : dossier d'installation modifiable par un utilisateur (" + installReason + ")");
            return 4;
        }

        if (!ServiceHostLock.TryAcquire())
        {
            AppLogger.Warn("Host", "Hôte de service refusé : verrou occupé ou ProgramData non fiable");
            return 5;
        }

        LocalizationService.Initialize();
        try
        {
            // Arrêt demandé par le service (pipe, jeton vérifié), fin du processus ou Ctrl+C :
            // dans tous les cas, l'hôte s'arrête proprement avant que le processus ne quitte.
            var stop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var container = new ProtectionHostContainer();
            using var host = new ProtectionServiceHost(container, () => stop.TrySetResult());
            host.Start();
            container.Logger.WriteToLog("[ServiceHost] Protection système active (IPC + RTP + processus)");

            AppDomain.CurrentDomain.ProcessExit += (_, _) => stop.TrySetResult();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                stop.TrySetResult();
            };
            await stop.Task.ConfigureAwait(false);
            await host.StopAsync().ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Error("Host", "Hôte de service arrêté sur erreur", ex);
            return 1;
        }
    }

    private static bool IsSystem()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch (System.Security.SecurityException)
        {
            return false;
        }
    }
}
