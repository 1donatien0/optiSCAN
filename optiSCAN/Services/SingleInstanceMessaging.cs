using System.Diagnostics;
using System.Runtime.InteropServices;

namespace optiSCAN.Services;

/// <summary>Messages Windows inter-instances (WPF ou WinUI).</summary>
public static class SingleInstanceMessaging
{
    public const int HwndBroadcast = 0xffff;

    private static readonly Lazy<int> WmShowMeLazy = new(() =>
        RegisterWindowMessage($"WM_SHOWME_OPTISCAN_{Process.GetCurrentProcess().SessionId}"));

    private static readonly Lazy<int> WmShellScanLazy = new(() =>
        RegisterWindowMessage($"WM_SHELLSCAN_OPTISCAN_{Process.GetCurrentProcess().SessionId}"));

    public static int WmShowMe => WmShowMeLazy.Value;

    public static int WmShellScan => WmShellScanLazy.Value;

    public static void NotifyShowExistingInstance() =>
        PostMessage((IntPtr)HwndBroadcast, WmShowMe, IntPtr.Zero, IntPtr.Zero);

    public static void NotifyShellScanRequest() =>
        PostMessage((IntPtr)HwndBroadcast, WmShellScan, IntPtr.Zero, IntPtr.Zero);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int RegisterWindowMessage(string message);
}
