using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace optiSCAN.Services
{
    /// <summary>
    /// Communication inter-instance basée sur un message Windows broadcast.
    /// Permet à une seconde instance qui se ferme aussitôt (App.xaml.cs) de
    /// faire remonter la fenêtre principale de la première instance.
    ///
    /// Avant ce refactor (audit A5), cette logique cohabitait dans MainWindow
    /// avec navigation, raccourcis, refresh — God Object 570 lignes.
    /// </summary>
    public static class IpcManager
    {
        public const int HWND_BROADCAST = 0xffff;
        public static readonly int WM_SHOWME = NativeMethods.RegisterWindowMessage("WM_SHOWME_OPTISCAN");

        /// <summary>
        /// Envoie le message "remonte la fenêtre" à toutes les fenêtres top-level.
        /// Appelé par la seconde instance qui se ferme.
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
