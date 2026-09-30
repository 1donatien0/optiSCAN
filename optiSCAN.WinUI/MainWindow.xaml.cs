using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using optiSCAN.Coordinators;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using optiSCAN.WinUI.ViewModels;
using optiSCAN.Views;
using optiSCAN.WinUI.Services;
using optiSCAN.WinUI.Views;
using System.Reflection;
using Windows.System;
using WinRT.Interop;

namespace optiSCAN.WinUI;

public sealed partial class MainWindow : Window
{
    private OverviewPage? _overviewPage;
    private AntivirusPage? _antivirusPage;
    private HistoryPage? _historyPage;
    private CleanPage? _cleanPage;
    private OptionsPage? _optionsPage;

    private readonly WinUiTrayHost _tray = new();
    private readonly WinUiServiceEventCoordinator _serviceEvents = new();
    private SignatureUpdateUiRunner _signatureUpdateRunner = null!;
    private readonly WinUiStatusFooterCoordinator _statusFooter = new();
    private WinUiNavigationService? _navigation;
    private WinUiShellScanCoordinator? _shellScan;
    private NavigationRefreshCoordinator? _navRefresh;
    private SignatureRefreshCoordinator? _signatureRefresh;
    private ExportCoordinator? _exportCoordinator;
    private AppWindow? _appWindow;
    private AntivirusViewModel? _antivirusViewModel;
    private IUserConfirmService? _confirm;
    private bool _explicitExit;
    private bool _startupDone;
    private bool _signatureUpdateRunning;
    private bool _shellReady;

    public MainWindow()
    {
        InitializeComponent();
        Title = "optiSCAN";
        VersionText.Text = $"v{Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "8.0.0"}";
        ApplyNavigationLabels();
        // La page d'accueil est créée dans InitializeShell, une fois les services prêts : créée ici,
        // elle recevait un service de confirmation nul (les corrections « Corriger » de la note de
        // sécurité étaient alors toujours refusées) et s'abonnait avant l'initialisation.
        RegisterKeyboardShortcuts();
        Activated += OnActivated;
    }

    private void RegisterKeyboardShortcuts() =>
        RootGrid.PreviewKeyDown += OnRootPreviewKeyDown;

    /// <summary>
    /// Ctrl+1…5 changent de section. Pas de KeyboardAccelerator sur la grille :
    /// WinUI en fait une infobulle « Ctrl+1 » sur tout survol sans info-bulle propre.
    /// </summary>
    private void OnRootPreviewKeyDown(object sender, KeyRoutedEventArgs e)
    {
        var ctrl = Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control);
        if (!ctrl.HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down))
            return;

        var tag = e.Key switch
        {
            VirtualKey.Number1 => "overview",
            VirtualKey.Number2 => "clean",
            VirtualKey.Number3 => "antivirus",
            VirtualKey.Number4 => "history",
            VirtualKey.Number5 => "options",
            _ => null
        };
        if (tag is null)
            return;

        e.Handled = true;
        SelectNavigation(tag);
    }

    private void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (_startupDone)
            return;

        _startupDone = true;
        InitializeShell();
    }

    private void InitializeShell()
    {
        var hwnd = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
        _appWindow = AppWindow.GetFromWindowId(windowId);
        _appWindow.Closing += AppWindow_Closing;
        _appWindow.Changed += AppWindow_Changed;

        if (_appWindow.Presenter is OverlappedPresenter presenter)
        {
            // Plancher bas : en dessous, le volet et les cartes ne tiennent plus.
            // Au-dessus, la page se réorganise et défile, le bord suit la souris.
            presenter.PreferredMinimumWidth = 720;
            presenter.PreferredMinimumHeight = 480;
        }

        _appWindow.Resize(new Windows.Graphics.SizeInt32(1280, 720));

        TryEnableMicaBackdrop();

        var host = WinUiServiceHost.Instance;
        _signatureUpdateRunner = host.Container.SignatureUpdateRunner;
        var ui = new WinUiThreadScheduler(DispatcherQueue);
        var confirm = new WinUiUserConfirmService(() => hwnd);
        _confirm = confirm;
        _antivirusViewModel = new AntivirusViewModel(host.Container, confirm, ui);
        _antivirusViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(AntivirusViewModel.IsScanning)
                or nameof(AntivirusViewModel.IsUpdating)
                or nameof(AntivirusViewModel.ScanProgressDetail))
                DispatcherQueue.TryEnqueue(RefreshLiveFooter);
        };
        host.InitializeUi(_antivirusViewModel, ui, confirm, dark =>
        {
            if (Content is FrameworkElement root)
                WinUiThemeManager.Apply(dark, root);
        });

        if (Content is FrameworkElement themeRoot)
            WinUiThemeManager.Initialize(host.Container.UserPreferencesAccessor, dark =>
                WinUiThemeManager.Apply(dark, themeRoot));

        // Changement de thème depuis Options : garder le bouton du volet cohérent.
        WinUiThemeManager.ThemeChanged += (_, _) => DispatcherQueue.TryEnqueue(UpdateThemeToggleLabel);

        _shellScan = new WinUiShellScanCoordinator(_antivirusViewModel, SelectNavigation, ShowWindow);

        _navigation = new WinUiNavigationService(SelectNavigation);
        host.Container.Navigation = _navigation;

        _exportCoordinator = new ExportCoordinator(new WinUiHistoryExportService(() => hwnd));
        _navRefresh = new NavigationRefreshCoordinator(
            _navigation,
            action => DispatcherQueue.TryEnqueue(() => action()),
            () => { WinUiServiceHost.Instance.History.Refresh(); return Task.CompletedTask; },
            () => { UpdateClamAvNavBadge(); return Task.CompletedTask; },
            () => RefreshAntivirusAsync(forceUpdate: false),
            () => RefreshAntivirusAsync(forceUpdate: false));

        _signatureRefresh = new SignatureRefreshCoordinator(
            host.Container.FreshclamUpdater,
            host.Container.RulesUpdater,
            host.Container.SignatureStatus,
            (_, line) => _antivirusPage?.AppendSignatureLog(line),
            (_, line) => _antivirusPage?.AppendSignatureLog(line),
            force => RefreshAntivirusAsync(force),
            RefreshLiveFooter,
            work => DispatcherQueue.TryEnqueue(async () => await work()));
        _signatureRefresh.Attach();

        _serviceEvents.Attach(
            host.Container,
            ServiceContainer.UiEvents,
            OnSignatureUpdateRequested,
            OnFocusAntivirusSignaturesRequested,
            OnFocusAntivirusScanTabRequested,
            OnHistoryRefreshRequested,
            OnExportHtmlRequested,
            OnExportPdfRequested,
            OnReviewHistorySession,
            OnOpenQuarantineTab,
            OnThreatDetected,
            OnUsbScanStatus,
            OnToastActivated,
            OnActionCompleted);

        ServiceContainer.UiEvents.ScanRequested += OnScanRequested;

        WinUiWindowMessageHook.Hook(this, SingleInstanceMessaging.WmShowMe, ShowWindow);
        WinUiWindowMessageHook.Hook(this, SingleInstanceMessaging.WmShellScan, () =>
            _ = _shellScan!.OnShellScanRequestedAsync());

        _tray.Initialize(hwnd, ShowWindow, ExitApplication);

        ApplySavedTheme();
        UpdateThemeToggleLabel();
        UpdateClamAvNavBadge();
        _shellReady = true;
        ShowSection((Navigation.SelectedItem as NavigationViewItem)?.Tag as string ?? "overview");
        _ = RunStartupAsync();
    }

    private void SetStatus(string message, bool isError, bool isWarning) =>
        _statusFooter.SetStatus(message, isError, isWarning, StatusText, StatusProgressRing, StatusIcon, () => false);

    private void RefreshLiveFooter() =>
        _statusFooter.RefreshLiveFooter(_antivirusViewModel, StatusText, StatusProgressRing, StatusIcon, () => _signatureUpdateRunning);

    private ExportContext BuildExportContext() => new(
        WinUiServiceHost.Instance.Container.Logger,
        (IEnumerable<ThreatInfo>?)_antivirusViewModel?.Threats ?? Array.Empty<ThreatInfo>(),
        WinUiServiceHost.Instance.Container.Quarantine.GetEntries(),
        SetStatus);

    private void AppWindow_Changed(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (_explicitExit || args.DidPresenterChange is not true)
            return;

        if (_appWindow?.Presenter is OverlappedPresenter presenter
            && presenter.State == OverlappedPresenterState.Minimized)
        {
            presenter.Restore();
            HideToTray();
        }
    }

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        if (WinUiThemeManager.IsAlternateThemeEnabled)
            WinUiThemeManager.SetSyncWithWindows(true);
        else
            WinUiThemeManager.SetAlternateThemeEnabled(true);

        if (Content is FrameworkElement root)
            WinUiThemeManager.Apply(WinUiThemeManager.IsDarkTheme, root);
        UpdateThemeToggleLabel();
        WinUiServiceHost.Instance.Options.RefreshThemeState();
    }

    private void UpdateThemeToggleLabel()
    {
        UpdateTitleBarColors();
        bool dark = WinUiThemeManager.IsDarkTheme;
        ThemeToggleIcon.Glyph = dark ? "\uE706" : "\uE708";
        ThemeToggleLabel.Text = dark
            ? LocalizationService.GetString("Opt_ThemeLight")
            : LocalizationService.GetString("Opt_ThemeDark");
    }

    /// <summary>
    /// La barre de titre système suit le thème de Windows, pas celui de l'app : en « thème opposé »
    /// on obtenait une barre blanche au-dessus d'une app sombre (et l'inverse). On l'aligne sur Donaby.
    /// </summary>
    private void UpdateTitleBarColors()
    {
        if (_appWindow == null || !AppWindowTitleBar.IsCustomizationSupported())
            return;

        try
        {
            bool dark = WinUiThemeManager.IsEffectiveDark;
            static Windows.UI.Color Rgb(byte r, byte g, byte b) => Windows.UI.Color.FromArgb(255, r, g, b);

            var background = (WinUiThemeManager.GetBrush("AppBackgroundBrush") as SolidColorBrush)?.Color
                ?? (dark ? Rgb(0x1C, 0x1C, 0x1C) : Rgb(0xF5, 0xF5, 0xF5));
            var foreground = dark ? Rgb(0xFF, 0xFF, 0xFF) : Rgb(0x1B, 0x1B, 0x1B);
            var inactive = (WinUiThemeManager.GetBrush("TextMutedBrush") as SolidColorBrush)?.Color ?? foreground;
            var hover = dark ? Rgb(0x2D, 0x2D, 0x2D) : Rgb(0xE5, 0xE5, 0xE5);
            var pressed = dark ? Rgb(0x38, 0x38, 0x38) : Rgb(0xD6, 0xD6, 0xD6);

            var bar = _appWindow.TitleBar;
            bar.BackgroundColor = background;
            bar.ForegroundColor = foreground;
            bar.InactiveBackgroundColor = background;
            bar.InactiveForegroundColor = inactive;
            bar.ButtonBackgroundColor = background;
            bar.ButtonForegroundColor = foreground;
            bar.ButtonInactiveBackgroundColor = background;
            bar.ButtonInactiveForegroundColor = inactive;
            bar.ButtonHoverBackgroundColor = hover;
            bar.ButtonHoverForegroundColor = foreground;
            bar.ButtonPressedBackgroundColor = pressed;
            bar.ButtonPressedForegroundColor = foreground;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindow", "UpdateTitleBarColors", ex);
        }
    }

    private void ApplyNavigationLabels()
    {
        NavOverview.Content = LocalizationService.GetString("Nav_Home");
        NavClean.Content = LocalizationService.GetString("Nav_Clean");
        NavAntivirusLabel.Text = LocalizationService.GetString("Nav_Antivirus");
        NavHistoryLabel.Text = LocalizationService.GetString("Nav_History");
        NavOptions.Content = LocalizationService.GetString("Nav_Options");
        FooterLangHint.Text = LocalizationService.IsEnglish ? "English" : "Français";
    }

    private void UpdateClamAvNavBadge()
    {
        try
        {
            var installed = WinUiServiceHost.Instance.Container.ClamAv.IsClamAvInstalled();
            ClamAvNavBadge.Text = installed
                ? LocalizationService.GetString("Main_ClamBadgeActive")
                : LocalizationService.GetString("Main_ClamBadgeMissing");
            // Suit le thème du volet (ActualTheme), plus une variante sombre imposée.
            ThemeBrush.SetForegroundKey(ClamAvNavBadge, installed ? "SuccessGreen" : "WarningBrush");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindow", "UpdateClamAvNavBadge", ex);
        }
    }

    private void OpenOptionsFooter_Click(object sender, RoutedEventArgs e) =>
        SelectNavigation("options");

    private void ApplySavedTheme()
    {
        // Thème appliqué via WinUiThemeManager.Initialize dans InitializeShell.
    }

    private async Task RunStartupAsync()
    {
        var host = WinUiServiceHost.Instance;
        try
        {
            await WinUiStartupCoordinator.RunAsync(new WinUiStartupCoordinator.Host
            {
                Container = host.Container,
                ViewModel = _antivirusViewModel!,
                RefreshOverview = () => _ = RefreshOverviewAsync(),
                RefreshAntivirus = () => _ = RefreshAntivirusAsync(),
                RefreshHistory = () => host.History.Refresh(),
                RefreshSignaturesAsync = () => RefreshAntivirusAsync(forceUpdate: false),
                SetStatus = SetStatus,
                WarmUpYaraRulesAsync = async () =>
                {
                    try
                    {
                        var yara = host.Container.Yara;
                        if (yara == null || !yara.IsAvailable || yara.HasCompiled)
                            return;
                        await yara.CompileRulesAsync(CancellationToken.None).ConfigureAwait(false);
                        DispatcherQueue.TryEnqueue(RefreshLiveFooter);
                    }
                    catch (Exception ex) { AppLogger.Warn("MainWindow", "WarmUpYaraRulesAsync", ex); }
                },
                PendingShellScanPath = App.PendingShellScanPath,
                RunShellScanAsync = path => _shellScan!.RunShellScanAsync(path),
                GuardSession = App.GuardSession,
                ShowOnboarding = () =>
                {
                    WinUiOnboardingService.ShowIfNeeded(_confirm!, host.Container);
                    // L'assistant peut changer les options (cohabitation Defender) : resynchroniser la page Options.
                    host.Options.ReloadPreferences();
                },
            }).ConfigureAwait(true);

            App.PendingShellScanPath = null;

            if (App.GuardSession)
                HideToTray();

            _overviewPage?.ApplyElevationBanner();
        }
        catch (Exception ex)
        {
            SetStatus(LocalizationService.Format("Status_Error", ex.Message), true, false);
            AppLogger.Error("MainWindow", "Startup", ex);
        }
    }

    public void ShowWindow()
    {
        _appWindow?.Show();
        Activate();
        SetStatus(OptiscanStrings.UiMessages.ProtectionActive, false, false);
    }

    private void HideToTray()
    {
        _appWindow?.Hide();
        SetStatus(OptiscanStrings.UiMessages.ProtectionReducedTray, false, true);
    }

    /// <summary>Message d'avertissement modal (MessageBox Win32 rattachée à la fenêtre).</summary>
    public void ShowWarning(string message, string title) => _confirm?.Warn(message, title);

    /// <summary>Relance optiSCAN en administrateur (UAC) puis ferme proprement l'instance courante.</summary>
    public void RestartElevated()
    {
        if (ElevationHelper.RelaunchElevated(App.RestartArgument))
            ExitApplication();
    }

    /// <summary>Fermeture complète : icône de notification, services, mutex d'instance unique.</summary>
    public void ExitApplication()
    {
        if (_explicitExit)
            return;
        _explicitExit = true;
        _navRefresh?.Detach();
        _signatureRefresh?.Detach();
        _serviceEvents.Detach();
        _tray.Dispose();
        _antivirusViewModel?.Dispose();
        try { WinUiServiceHost.Instance.Container.Shutdown(); }
        catch (Exception ex) { AppLogger.Warn("MainWindow", "Shutdown", ex); }
        App.ReleaseInstanceMutex();
        Close();
        Application.Current.Exit();
    }

    private void AppWindow_Closing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_explicitExit)
            return;

        args.Cancel = true;
        HideToTray();
    }

    private void Navigation_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item || item.Tag is not string tag)
            return;

        ShowSection(tag);
    }

    private void ShowSection(string tag)
    {
        // Avant InitializeShell, les services (confirmation, navigation, VM antivirus) n'existent pas encore.
        if (PageHost is null || StatusText is null || !_shellReady)
            return;

        PageHost.Content = tag switch
        {
            "overview" => GetOverviewPage(),
            "antivirus" => GetAntivirusPage(),
            "history" => GetHistoryPage(),
            "clean" => GetCleanPage(),
            "options" => GetOptionsPage(),
            _ => new PlaceholderPage("Accueil", "Section non reconnue.")
        };

        _navigation?.NotifyPanelShown(tag);
        _overviewPage?.ApplyElevationBanner();
    }

    private OverviewPage GetOverviewPage()
    {
        _overviewPage ??= new OverviewPage(_confirm);
        _ = RefreshOverviewAsync();
        return _overviewPage;
    }

    private AntivirusPage GetAntivirusPage()
    {
        if (_antivirusPage != null)
            return _antivirusPage;

        _antivirusPage = new AntivirusPage(_antivirusViewModel!, _confirm);
        _ = RefreshAntivirusAsync();
        return _antivirusPage;
    }

    private HistoryPage GetHistoryPage()
    {
        _historyPage ??= new HistoryPage(WinUiServiceHost.Instance.History, _confirm);
        _historyPage.Refresh();
        return _historyPage;
    }

    private CleanPage GetCleanPage() =>
        _cleanPage ??= new CleanPage(WinUiServiceHost.Instance.Clean);

    private OptionsPage GetOptionsPage() =>
        _optionsPage ??= new OptionsPage(WinUiServiceHost.Instance.Options);

    public void SelectNavigation(string tag)
    {
        foreach (var item in Navigation.MenuItems)
        {
            if (item is NavigationViewItem navItem && navItem.Tag as string == tag)
            {
                Navigation.SelectedItem = navItem;
                return;
            }
        }

        ShowSection(tag);
    }

    private async Task RefreshOverviewAsync()
    {
        if (_overviewPage == null)
            return;

        try
        {
            await WinUiServiceHost.Instance.RefreshOverviewAsync(_overviewPage).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetStatus(LocalizationService.Format("Status_Error", ex.Message), true, false);
        }
        finally
        {
            UpdateClamAvNavBadge();
            RefreshLiveFooter();
        }
    }

    private async Task RefreshAntivirusAsync(bool forceUpdate = false)
    {
        try
        {
            await WinUiServiceHost.Instance.RefreshAntivirusAsync(_antivirusPage, forceUpdate).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetStatus(LocalizationService.Format("Status_Error", ex.Message), true, false);
        }
        finally
        {
            UpdateClamAvNavBadge();
            RefreshLiveFooter();
        }
    }

    private void OnExportHtmlRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => _exportCoordinator?.TryExportHtml(BuildExportContext()));

    private void OnExportPdfRequested(object? sender, ScanSession session) =>
        DispatcherQueue.TryEnqueue(() => _exportCoordinator?.TryExportSessionPdf(BuildExportContext(), session));

    private void OnSignatureUpdateRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => _ = RunManualSignatureUpdateAsync());

    private void OnFocusAntivirusSignaturesRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("antivirus");
            (_antivirusPage ?? GetAntivirusPage()).SelectSignaturesTab();
        });

    /// <summary>Lance une analyse demandée depuis une autre vue (accueil, note de sécurité).</summary>
    private void OnScanRequested(object? sender, ScanType type) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("antivirus");
            (_antivirusPage ?? GetAntivirusPage()).SelectScanTab();
            var command = type == ScanType.FullScan
                ? _antivirusViewModel?.FullScanCommand
                : _antivirusViewModel?.QuickScanCommand;
            command?.Execute(null);
        });

    private void OnFocusAntivirusScanTabRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("antivirus");
            (_antivirusPage ?? GetAntivirusPage()).SelectScanTab();
        });

    public void StopSignatureUpdate()
    {
        var page = _antivirusPage;
        var host = WinUiServiceHost.Instance.Container;
        ManualSignatureUpdateCoordinator.Stop(new ManualSignatureUpdateCoordinator.StopHost
        {
            Freshclam = host.FreshclamUpdater,
            Rules = host.RulesUpdater,
            SetStatus = (msg, _, _, _) => SetStatus(msg, false, false),
            AppendSignatureLog = line => page?.AppendSignatureLog(line),
            SetSignatureUpdating = updating => page?.SetSignatureUpdating(updating),
        });
        // (La ligne « interrompue » est déjà écrite par ManualSignatureUpdateCoordinator.Stop.)
        _signatureUpdateRunning = false;
        RefreshLiveFooter();
    }

    private async Task RunManualSignatureUpdateAsync()
    {
        var page = _antivirusPage ?? GetAntivirusPage();
        var host = WinUiServiceHost.Instance;
        _signatureUpdateRunning = true;
        RefreshLiveFooter();
        try
        {
            await ManualSignatureUpdateCoordinator.RunAsync(new ManualSignatureUpdateCoordinator.Host
            {
                Runner = _signatureUpdateRunner,
                Freshclam = host.Container.FreshclamUpdater,
                Rules = host.Container.RulesUpdater,
                SignatureStatus = host.Container.SignatureStatus,
                SetStatus = (msg, _, _, _) => SetStatus(msg, false, false),
                RefreshLiveFooter = RefreshLiveFooter,
                RefreshSignaturesDisplayAsync = force => RefreshAntivirusAsync(force),
                SetSignatureUpdating = updating => page.SetSignatureUpdating(updating),
                AppendSignatureLog = line => page.AppendSignatureLog(line),
            }).ConfigureAwait(true);
        }
        finally
        {
            _signatureUpdateRunning = false;
            RefreshLiveFooter();
        }
    }

    private void OnHistoryRefreshRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => WinUiServiceHost.Instance.History.Refresh());

    private void OnReviewHistorySession(object? sender, ScanSession session)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            _antivirusViewModel?.LoadThreatsFromHistorySession(session);
            SelectNavigation("antivirus");
            GetAntivirusPage().SelectScanTab();
        });
    }

    private void OnOpenQuarantineTab(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("antivirus");
            _antivirusPage?.SelectQuarantineTab();
            _antivirusViewModel?.RefreshQuarantineList();
        });
    }

    private void OnThreatDetected(object? sender, ThreatInfo threat)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            RealTimeThreatCoordinator.Handle(threat, new RealTimeThreatCoordinator.Host
            {
                LiveThreatSink = _antivirusViewModel,
                RefreshQuarantineList = () => _antivirusViewModel?.RefreshQuarantineList(),
                RefreshOverviewProtection = () => _ = RefreshOverviewAsync(),
            });
            SetStatus(LocalizationService.Format("Rtp_ThreatToastTitle", threat.VirusName), false, false);
            RefreshLiveFooter();
        });
    }

    private void OnUsbScanStatus(object? sender, RemovableDriveScanStatusEventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            UsbScanStatusCoordinator.Handle(e, new UsbScanStatusCoordinator.Host
            {
                SetStatus = (text, _, _, _) => SetStatus(text, false, false),
            });
            RefreshLiveFooter();
        });
    }

    private void OnToastActivated(object? sender, ToastActivationEventArgs e) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_navigation is null)
                return;

            ToastActivationCoordinator.Handle(e, new ToastActivationCoordinator.Host
            {
                Services = WinUiServiceHost.Instance.Container,
                Navigation = _navigation,
                ShowWindow = ShowWindow,
                SetStatus = (msg, isError, isWarning) => SetStatus(msg, isError, isWarning),
                RefreshQuarantineList = () => _antivirusViewModel?.RefreshQuarantineList(),
                RefreshAntivirusView = () => _ = RefreshAntivirusAsync(),
                SelectAntivirusScanTab = () =>
                {
                    SelectNavigation("antivirus");
                    _antivirusPage?.SelectScanTab();
                },
                SelectAntivirusQuarantineTab = () =>
                {
                    SelectNavigation("antivirus");
                    _antivirusPage?.SelectQuarantineTab();
                    _antivirusViewModel?.RefreshQuarantineList();
                },
                SelectAntivirusSignaturesTab = () =>
                {
                    SelectNavigation("antivirus");
                    _antivirusPage?.SelectSignaturesTab();
                },
                TriggerManualSignatureUpdate = () => _ = RunManualSignatureUpdateAsync(),
            });
        });

    private void OnActionCompleted(object? sender, ActionResult result)
    {
        DispatcherQueue.TryEnqueue(() =>
            AntivirusActionResultCoordinator.Handle(result, new AntivirusActionResultCoordinator.Host
            {
                SetStatus = (msg, _, _) => SetStatus(msg, false, false),
                RefreshQuarantineList = () => _antivirusViewModel?.RefreshQuarantineList(),
                RefreshHistory = () => WinUiServiceHost.Instance.History.Refresh(),
                RefreshAntivirusData = () => _ = RefreshAntivirusAsync(),
            }));
    }

    private void TryEnableMicaBackdrop()
    {
        try
        {
            if (MicaController.IsSupported())
                SystemBackdrop = new MicaBackdrop { Kind = MicaKind.Base };
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindow", "MicaBackdrop", ex);
        }
    }
}
