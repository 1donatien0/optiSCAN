// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace optiSCAN.Native;

/// <summary>
/// Appels Win32 isolés du moteur (écran, réseau, chemins longs). Les modules natifs complets
/// restent dans leur enveloppe dédiée : <c>ClamdIsolation</c> (AppContainer, objets job),
/// <c>SafePathDelete</c> et <c>RealTimePathGuard</c> (descente NT sans lien),
/// <c>NamedPipeClientAccess</c>, <c>PipeServerAccount</c> et <c>ProtectionPipeAcl</c> (tube),
/// <c>MinifilterUserBridge</c> (pilote). Aucune autre classe du moteur ne déclare de P/Invoke.
/// </summary>
internal static class NativeMethods
{
    internal const uint MonitorDefaultToNearest = 2;

    [StructLayout(LayoutKind.Sequential)]
    internal struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll")]
    internal static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    internal static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetMonitorInfo(IntPtr monitor, ref MONITORINFO info);

    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = false)]
    internal static extern uint DnsFlushResolverCache();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetLongPathName(string shortPath, char[] longPath, int bufferLength);
}
