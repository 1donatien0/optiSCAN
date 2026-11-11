// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using System.Windows;
using System.Windows.Threading;

namespace optiSCAN.Coordinators;

/// <summary>Scan menu contextuel Explorateur (IPC second instance + chemin en attente au démarrage).</summary>
public sealed class ShellScanCoordinator
{
    private readonly Dispatcher _dispatcher;
    private readonly NavigationService _navigation;
    private readonly Func<ScanViewModel?> _viewModel;
    private readonly Action _showWindow;

    public ShellScanCoordinator(
        Dispatcher dispatcher,
        NavigationService navigation,
        Func<ScanViewModel?> viewModel,
        Action showWindow)
    {
        _dispatcher = dispatcher;
        _navigation = navigation;
        _viewModel = viewModel;
        _showWindow = showWindow;
    }

    public void Hook(Window window) =>
        IpcManager.HookShellScanRequest(window, OnShellScanRequested);

    private bool _draining;

    private void OnShellScanRequested()
    {
        _dispatcher.BeginInvoke(async () =>
        {
            await DrainQueueAsync();
            _showWindow();
        }, DispatcherPriority.Normal);
    }

    /// <summary>
    /// Analyse une à une toutes les demandes en attente (sélection multiple dans l'Explorateur :
    /// un processus, donc une demande, par élément). Une seule boucle à la fois : les demandes
    /// arrivées pendant une analyse sont reprises par la boucle en cours au lieu d'être ignorées
    /// (StartScanAsync ne lance rien tant qu'une analyse tourne).
    /// </summary>
    public async Task DrainQueueAsync()
    {
        if (_draining)
            return;
        _draining = true;
        try
        {
            while (true)
            {
                var paths = ShellScanRequest.TryConsumeAll();
                if (paths.Count == 0)
                    break;
                foreach (var path in paths)
                    await RunShellScanAsync(path);
            }
        }
        finally
        {
            _draining = false;
        }
    }

    public async Task RunShellScanAsync(string path)
    {
        var vm = _viewModel();
        if (vm == null || !ShellScanArguments.IsValidScanTarget(path))
            return;

        _navigation.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
        _showWindow();
        await vm.RequestContextMenuScanAsync(path);
    }
}
