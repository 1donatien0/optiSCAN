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

        private const uint MsgfltAllow = 1;

        private static readonly Lazy<int> WmShowMeLazy = new(() =>
            NativeMethods.RegisterWindowMessage(
                $"WM_SHOWME_OPTISCAN_{Process.GetCurrentProcess().SessionId}"));

        private static readonly Lazy<int> WmShellScanLazy = new(() =>
            NativeMethods.RegisterWindowMessage(
                $"WM_SHELLSCAN_OPTISCAN_{Process.GetCurrentProcess().SessionId}"));

        public static int WM_SHOWME => WmShowMeLazy.Value;

        public static int WM_SHELL_SCAN => WmShellScanLazy.Value;

        /// <summary>
        /// Envoie le message « remonte la fenêtre » aux fenêtres top-level de la session courante.
        /// </summary>
        public static void NotifyShowExistingInstance()
        {
            NativeMethods.PostMessage((IntPtr)HWND_BROADCAST, WM_SHOWME, IntPtr.Zero, IntPtr.Zero);
        }

        /// <summary>Demande à l'instance principale de lancer un scan menu contextuel.</summary>
        public static void NotifyShellScanRequest()
        {
            NativeMethods.PostMessage((IntPtr)HWND_BROADCAST, WM_SHELL_SCAN, IntPtr.Zero, IntPtr.Zero);
        }

        /// <summary>
        /// Branche un hook WndProc sur la fenêtre passée pour détecter le
        /// message WM_SHOWME et exécuter <paramref name="onShow"/>.
        /// </summary>
        public static void HookShowMessage(Window window, Action onShow) =>
            HookMessage(window, WM_SHOWME, onShow);

        /// <summary>Écoute les demandes de scan depuis une seconde instance (Explorateur).</summary>
        public static void HookShellScanRequest(Window window, Action onShellScan) =>
            HookMessage(window, WM_SHELL_SCAN, onShellScan);

        private static void HookMessage(Window window, int messageId, Action handler)
        {
            window.SourceInitialized += (_, _) =>
            {
                if (PresentationSource.FromVisual(window) is HwndSource src)
                {
                    // Fenêtre élevée : Windows bloque par défaut les messages d'un processus moins
                    // élevé (seconde instance lancée normalement, menu contextuel). Ce message-là
                    // seul est autorisé, sans quoi la fenêtre ne se rouvrait pas.
                    try { NativeMethods.ChangeWindowMessageFilterEx(src.Handle, messageId, MsgfltAllow, IntPtr.Zero); }
                    catch (Exception ex) { AppLogger.Debug("IpcManager", "Filtre de message : " + ex.Message); }

                    src.AddHook((IntPtr h, int m, IntPtr w, IntPtr l, ref bool handled) =>
                    {
                        if (m == messageId)
                        {
                            try { handler(); } catch (Exception ex) { AppLogger.Warn("IpcManager", "HookMessage", ex); }
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

            [DllImport("user32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, int message, uint action, IntPtr changeFilterStruct);
        }
    }
}
