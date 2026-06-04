using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace optiSCAN.Services
{
    /// <summary>
    /// Communication inter-instance : message Windows pour qu’une seconde instance
    /// en cours de fermeture demande à la première de réafficher sa fenêtre principale.
    /// </summary>
    public static class IpcManager
    {
        public const int HWND_BROADCAST = 0xffff;

        private static readonly Lazy<int> WmShowMeLazy = new(() =>
            NativeMethods.RegisterWindowMessage(
                $"WM_SHOWME_OPTISCAN_{Process.GetCurrentProcess().SessionId}"));

        public static int WM_SHOWME => WmShowMeLazy.Value;

        /// <summary>
        /// Envoie le message « remonte la fenêtre » aux fenêtres top-level de la session courante.
        /// </summary>
        public static void NotifyShowExistingInstance()
        {
            NativeMethods.PostMessage((IntPtr)HWND_BROADCAST, WM_SHOWME, IntPtr.Zero, IntPtr.Zero);
        }

        /// <summary>
        /// Branche un hook WndProc sur la fenêtre passée pour détecter le
        /// message WM_SHOWME et exécuter <paramref name="onShow"/>.
        /// </summary>
        public static void HookShowMessage(Window window, Action onShow)
        {
            window.SourceInitialized += (_, _) =>
            {
                if (PresentationSource.FromVisual(window) is HwndSource src)
                {
                    src.AddHook((IntPtr h, int m, IntPtr w, IntPtr l, ref bool handled) =>
                    {
                        if (m == WM_SHOWME)
                        {
                            try { onShow(); } catch (Exception ex) { AppLogger.Warn("IpcManager", "onShow", ex); }
                            handled = true;
                        }
                        return IntPtr.Zero;
                    });
                }
            };
        }

        private static class NativeMethods
        {
            [DllImport("user32.dll")]
            public static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern int RegisterWindowMessage(string message);
        }
    }
}
