// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace optiSCAN.Native;

/// <summary>Appels Win32 propres à l'interface (coquille Windows et seconde instance).</summary>
internal static class UiNativeMethods
{
    [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
    internal static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int RegisterWindowMessage(string message);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, int message, uint action, IntPtr changeFilterStruct);
}
