using Microsoft.Extensions.DependencyInjection;
using optiSCAN.Localization;
using optiSCAN.Services.DependencyInjection;

namespace optiSCAN.Services
{
    /// <summary>
    /// Composition de l'hôte SYSTEM (<c>optiSCAN.Host.exe --service-host</c>) : uniquement les
    /// services du moteur, sans interface, sans singleton global. L'hôte suit la politique de
    /// l'administrateur (<see cref="HostPolicyStore"/>) et rien d'autre.
    /// </summary>
    public sealed class ProtectionHostContainer : IProtectionServiceHostDependencies, IDisposable
    {
        private readonly ServiceProvider _services;
        private bool _shutdownDone;

        public ProtectionHostContainer()
        {
            var collection = new ServiceCollection();
            collection.AddSingleton<INotificationSink, LogNotificationSink>();
            collection.AddOptiscanEngineServices();
            _services = collection.BuildServiceProvider();

            UserPreferencesAccessor = _services.GetRequiredService<IUserPreferencesAccessor>();
            ExclusionSettingsAccessor = _services.GetRequiredService<IExclusionSettingsAccessor>();
            DistractionFreeMonitor.Initialize(UserPreferencesAccessor);
            PlatformProtectionBootstrap.Initialize(UserPreferencesAccessor);
            LocalizationService.ConfigurePreferencesAccessor(UserPreferencesAccessor);

            FreshclamUpdater = _services.GetRequiredService<FreshclamUpdater>();
            RulesUpdater = _services.GetRequiredService<YaraForgeUpdater>();
            Yara = _services.GetRequiredService<YaraEngine>();
            Quarantine = _services.GetRequiredService<QuarantineManager>();
            Logger = _services.GetRequiredService<ScanLogManager>();
            CloudThreatIntel = _services.GetRequiredService<CloudThreatIntelService>();
            Orchestrator = _services.GetRequiredService<ScanOrchestrator>();
            RealTimeProtection = _services.GetRequiredService<RealTimeProtection>();
            ProcessStartMonitor = _services.GetRequiredService<ProcessStartMonitor>();
            RemovableDriveScan = _services.GetRequiredService<RemovableDriveScanService>();

            var activity = _services.GetRequiredService<ActivityLogService>();
            Logger.BindActivityLog(activity);
            Quarantine.BindActivityLog(activity);
            activity.EnsureMigrated(Quarantine);

            var yara = Yara;
            _ = Task.Run(async () =>
            {
                try { await yara.CompileRulesAsync().ConfigureAwait(false); }
                catch (Exception ex) { AppLogger.Warn("ProtectionHostContainer", "Précompilation YARA", ex); }
            });
            AppLogger.Info("ProtectionHostContainer", "Services de l'hôte initialisés (sans interface)");
        }

        public FreshclamUpdater FreshclamUpdater { get; }
        public YaraForgeUpdater RulesUpdater { get; }
        public YaraEngine Yara { get; }
        public QuarantineManager Quarantine { get; }
        public ScanLogManager Logger { get; }
        public CloudThreatIntelService CloudThreatIntel { get; }
        public ScanOrchestrator Orchestrator { get; }
        public RealTimeProtection RealTimeProtection { get; }
        public ProcessStartMonitor ProcessStartMonitor { get; }
        public RemovableDriveScanService RemovableDriveScan { get; }
        public IUserPreferencesAccessor UserPreferencesAccessor { get; }
        public IExclusionSettingsAccessor ExclusionSettingsAccessor { get; }

        /// <summary>Réservé à l'interface : l'hôte démarre par <see cref="ApplyHostPreferences"/>.</summary>
        public void ApplyPreferencesOnStartup() => ApplyHostPreferences();

        public void ApplyHostPreferences()
        {
            HostPolicyStore.Changed -= OnHostPolicyChanged;
            HostPolicyStore.Changed += OnHostPolicyChanged;
            // Reprise du dossier (et purge de ce qui y a été déposé) avant toute lecture.
            if (!optiSCAN.Platform.OptiScanProgramData.EnsureTrusted())
                throw new InvalidOperationException("Le dossier ProgramData d'optiSCAN n'a pas pu être sécurisé.");
            if (HostPolicyStore.TryRead(out var policy))
                CopyHostPolicy(policy);

            ApplyPolicy();
            SignatureUpdatePolicy.NotifyAndScheduleStartupRefresh(FreshclamUpdater, RulesUpdater, UserPreferencesAccessor);
        }

        private void OnHostPolicyChanged(HostPolicy policy)
        {
            CopyHostPolicy(policy);
            ApplyPolicy();
        }

        private void CopyHostPolicy(HostPolicy policy)
        {
            ExclusionSettingsAccessor.Current.RealTimeEnabled = policy.RealTimeEnabled;
            ExclusionSettingsAccessor.Current.AutoQuarantineEnabled = policy.AutoQuarantineEnabled;
            UserPreferencesAccessor.Current.ProcessMonitorEnabled = policy.ProcessMonitorEnabled;
            UserPreferencesAccessor.Current.SignatureAutoUpdateEnabled = policy.SignatureAutoUpdateEnabled;
            UserPreferencesAccessor.Current.RemovableDriveScanEnabled = policy.RemovableDriveScanEnabled;
        }

        private void ApplyPolicy()
        {
            var prefs = UserPreferencesAccessor.Current;
            SignatureUpdatePolicy.ApplyAutoUpdateTimers(FreshclamUpdater, RulesUpdater, prefs.SignatureAutoUpdateEnabled, UserPreferencesAccessor);

            if (ExclusionSettingsAccessor.Current.RealTimeEnabled)
            {
                RealTimeProtection.Start();
                if (prefs.ProcessMonitorEnabled)
                    ProcessStartMonitor.Start();
                else
                    ProcessStartMonitor.Stop();
            }
            else
            {
                RealTimeProtection.Stop();
                ProcessStartMonitor.Stop();
            }

            if (prefs.GameModeAutoEnabled)
                DistractionFreeMonitor.Start();
            else
                DistractionFreeMonitor.Stop();

            if (prefs.UseClamdEngine)
            {
                _ = Task.Run(async () =>
                {
                    try { await ClamdHost.Shared.EnsureRunningAsync().ConfigureAwait(false); }
                    catch (Exception ex) { AppLogger.Warn("ProtectionHostContainer", "Préchauffage clamd", ex); }
                });
            }

            if (prefs.RemovableDriveScanEnabled)
                RemovableDriveScan.Start();
            else
                RemovableDriveScan.Stop();
        }

        public void Shutdown()
        {
            if (_shutdownDone)
                return;
            _shutdownDone = true;
            HostPolicyStore.Changed -= OnHostPolicyChanged;
            Stop("RealTimeProtection", RealTimeProtection.Dispose);
            Stop("ProcessStartMonitor", ProcessStartMonitor.Dispose);
            Stop("RemovableDriveScan", RemovableDriveScan.Dispose);
            Stop("FreshclamUpdater", FreshclamUpdater.DisableAutoUpdate);
            Stop("RulesUpdater", RulesUpdater.DisableAutoUpdate);
            Stop("ClamdHost", ClamdHost.Shared.Stop);
            Stop("DistractionFreeMonitor", DistractionFreeMonitor.Stop);
            _services.Dispose();
            AppLogger.Info("ProtectionHostContainer", "Services de l'hôte fermés");
        }

        public void Dispose() => Shutdown();

        private static void Stop(string name, Action action)
        {
            try { action(); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                AppLogger.Warn("ProtectionHostContainer", name, ex);
            }
        }
    }
}
