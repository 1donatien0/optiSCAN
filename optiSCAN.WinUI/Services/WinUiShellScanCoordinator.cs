using optiSCAN.Services;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Services;

public sealed class WinUiShellScanCoordinator
{
    private readonly AntivirusViewModel _viewModel;
    private readonly Action<string> _navigateToAntivirus;
    private readonly Action _showWindow;

    public WinUiShellScanCoordinator(AntivirusViewModel viewModel, Action<string> navigateToAntivirus, Action showWindow)
    {
        _viewModel = viewModel;
        _navigateToAntivirus = navigateToAntivirus;
        _showWindow = showWindow;
    }

    public async Task RunShellScanAsync(string path)
    {
        if (!ShellScanArguments.IsValidScanTarget(path))
            return;

        _navigateToAntivirus("antivirus");
        _showWindow();
        await _viewModel.RequestContextMenuScanAsync(path).ConfigureAwait(true);
    }

    public async Task OnShellScanRequestedAsync()
    {
        var path = ShellScanRequest.TryConsume();
        if (!string.IsNullOrWhiteSpace(path))
            await RunShellScanAsync(path).ConfigureAwait(true);
        _showWindow();
    }
}
