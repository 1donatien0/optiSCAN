// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace optiSCAN.Native;

/// <summary>Appels Win32 propres à l'interface (coquille Windows).</summary>
internal static class UiNativeMethods
{
    [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
    internal static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
}
