using System.Runtime.InteropServices;
using optiSCAN.Services;

namespace optiSCAN.WinUI.Services;

/// <summary>Confirmations utilisateur synchrones via MessageBox Win32 (parent = fenêtre WinUI).</summary>
public sealed class WinUiUserConfirmService : IUserConfirmService
{
    private readonly Func<IntPtr> _getHwnd;

    public WinUiUserConfirmService(Func<IntPtr> getHwnd) => _getHwnd = getHwnd;

    public bool ConfirmYesNo(string message, string title, bool warning = true)
    {
        var flags = MB_YESNO | (warning ? MB_ICONWARNING : MB_ICONQUESTION) | MB_DEFBUTTON2;
        return MessageBoxW(_getHwnd(), message, title, flags) == IDYES;
    }

    public void Inform(string message, string title) =>
        MessageBoxW(_getHwnd(), message, title, MB_OK | MB_ICONINFORMATION);

    public void Warn(string message, string title) =>
        MessageBoxW(_getHwnd(), message, title, MB_OK | MB_ICONWARNING);

    private const uint MB_OK = 0x00000000;

    private const uint MB_YESNO = 0x00000004;
    private const uint MB_ICONWARNING = 0x00000030;
    private const uint MB_ICONQUESTION = 0x00000020;
    private const uint MB_ICONINFORMATION = 0x00000040;
    private const uint MB_DEFBUTTON2 = 0x00000100;
    private const int IDYES = 6;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
