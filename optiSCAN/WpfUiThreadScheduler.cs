// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Threading;
using optiSCAN.Services;
using WpfApp = System.Windows.Application;

namespace optiSCAN;

/// <summary>Planifie du travail sur le Dispatcher WPF.</summary>
public sealed class WpfUiThreadScheduler : IUiThreadScheduler
{
    public static WpfUiThreadScheduler Instance { get; } = new();

    public void Invoke(Action action)
    {
        var dispatcher = WpfApp.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
            action();
        else
            dispatcher.Invoke(action);
    }

    public void BeginInvoke(Action action)
    {
        var dispatcher = WpfApp.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
            action();
        else
            dispatcher.BeginInvoke(action, DispatcherPriority.Background);
    }
}
