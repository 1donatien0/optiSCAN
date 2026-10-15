using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Services;

/// <summary>
/// Ouvre le fichier demandé avec le jeton du client du pipe, pas avec celui du service.
/// </summary>
internal static class NamedPipeClientAccess
{
    /// <summary>
    /// Ouvre le fichier avec le jeton du client et rend la poignée. Le contrôle d'accès
    /// a lieu à l'ouverture : la poignée reste lisible après RevertToSelf, et elle désigne
    /// le fichier vu par le client, même si le chemin est remplacé ensuite.
    /// </summary>
    internal static FileStream? OpenForClient(NamedPipeServerStream pipe, string fullPath)
    {
        if (ImpersonateNamedPipeClient(pipe.SafePipeHandle))
        {
            try
            {
                return TryOpen(fullPath);
            }
            finally
            {
                RevertToSelf();
            }
        }

        // Même processus : il n'y a pas de jeton distinct à usurper (tests, hôte local).
        if (GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid)
            && clientPid == (uint)Environment.ProcessId)
            return TryOpen(fullPath);

        return null;
    }

    /// <summary>
    /// Ouvre un chemin sous le jeton du processus qui a déclenché la surveillance, afin que
    /// le service SYSTEM ne puisse pas analyser des octets inaccessibles à ce processus.
    /// </summary>
    internal static FileStream? OpenForProcess(int processId, string fullPath)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        try
        {
            using var process = Process.GetProcessById(processId);
            if (!OpenProcessToken(process.SafeHandle, TokenDuplicate | TokenQuery, out var primaryToken))
            {
                // Processus protégé (PPL) ou jeton inaccessible : le binaire n'est pas analysé.
                // Ce trou de couverture est journalisé au lieu d'être silencieux.
                AppLogger.Info("NamedPipeClientAccess",
                    $"Jeton du processus {processId} inaccessible (processus protégé ?) : lancement non analysé ({PathRedaction.RedactPath(fullPath)})");
                return null;
            }

            using (primaryToken)
            {
                if (!DuplicateTokenEx(
                        primaryToken,
                        TokenImpersonate | TokenQuery,
                        IntPtr.Zero,
                        SecurityImpersonationLevel.SecurityImpersonation,
                        TokenType.TokenImpersonation,
                        out var impersonationToken))
                    return null;

                using (impersonationToken)
                    return WindowsIdentity.RunImpersonated(impersonationToken, () => TryOpen(fullPath));
            }
        }
        catch
        {
            // Le processus a pu quitter ou son jeton n'est plus accessible.
            return null;
        }
    }

    /// <summary>
    /// Crée le fichier de restauration <b>sous le jeton du client</b> (un administrateur élevé),
    /// jamais avec les droits du service : le service SYSTEM n'écrit pas lui-même dans un
    /// dossier que l'utilisateur contrôle. Création neuve, sans traverser de jonction, puis
    /// contrôle du chemin réel : voir <see cref="RestoreFileWriter"/>.
    /// </summary>
    internal static IRestoreTarget? CreateNewForClient(NamedPipeServerStream pipe, string fullPath)
    {
        SafeFileHandle? handle = null;
        if (ImpersonateNamedPipeClient(pipe.SafePipeHandle))
        {
            try
            {
                handle = RestoreFileWriter.TryCreateHandle(fullPath);
            }
            finally
            {
                RevertToSelf();
            }
        }
        else if (GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid)
                 && clientPid == (uint)Environment.ProcessId)
        {
            handle = RestoreFileWriter.TryCreateHandle(fullPath);
        }

        return handle == null ? null : RestoreFileWriter.Validate(handle, fullPath);
    }

    private static FileStream? TryOpen(string fullPath)
    {
        try
        {
            // Refuser les écritures ou remplacements concurrents pendant la copie de staging.
            return new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Compte du processus client, pour répartir les places d'écoute et le débit de scan
    /// par compte. Lu sur le jeton du processus : aucune donnée du client n'est nécessaire.
    /// </summary>
    internal static string GetClientAccount(NamedPipeServerStream pipe)
    {
        const uint QueryLimitedInformation = 0x1000;
        const uint TokenQuery = 0x0008;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid))
            return UnknownAccount;
        if (pid == (uint)Environment.ProcessId)
            return SelfAccount;

        var process = OpenProcess(QueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero)
            return UnknownAccount;
        try
        {
            if (!OpenProcessToken(process, TokenQuery, out var token))
                return UnknownAccount;
            try
            {
                using var identity = new WindowsIdentity(token);
                return identity.User?.Value ?? UnknownAccount;
            }
            finally
            {
                CloseHandle(token);
            }
        }
        catch
        {
            return UnknownAccount;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    /// <summary>
    /// SID du client lu sur son jeton usurpé (<c>ImpersonateNamedPipeClient</c>), donc lié à la
    /// connexion et non à un PID qui peut avoir été réutilisé. Null si l'usurpation échoue.
    /// </summary>
    internal static string? GetImpersonatedClientSid(NamedPipeServerStream pipe)
    {
        if (!ImpersonateNamedPipeClient(pipe.SafePipeHandle))
            return null;
        try
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            return identity.User?.Value;
        }
        catch
        {
            return null;
        }
        finally
        {
            RevertToSelf();
        }
    }

    internal const string UnknownAccount = "?";
    internal const string SelfAccount = "self";
    internal const string SystemAccount = "S-1-5-18";

    private const uint TokenDuplicate = 0x0002;
    private const uint TokenImpersonate = 0x0004;
    private const uint TokenQuery = 0x0008;

    private enum SecurityImpersonationLevel
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation,
    }

    private enum TokenType
    {
        TokenPrimary = 1,
        TokenImpersonation,
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle process,
        uint access,
        out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        SafeAccessTokenHandle existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        SecurityImpersonationLevel impersonationLevel,
        TokenType tokenType,
        out SafeAccessTokenHandle newToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>
    /// set_policy change le service SYSTEM. Seul un administrateur élevé, ou SYSTEM, peut l'envoyer.
    /// </summary>
    internal static bool IsElevatedAdministrator(NamedPipeServerStream pipe)
    {
        if (ImpersonateNamedPipeClient(pipe.SafePipeHandle))
        {
            try
            {
                return CurrentProcessIsElevatedAdministrator();
            }
            finally
            {
                RevertToSelf();
            }
        }

        if (GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid)
            && clientPid == (uint)Environment.ProcessId)
            return CurrentProcessIsElevatedAdministrator();

        return false;
    }

    internal static bool CurrentProcessIsElevatedAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.IsSystem)
                return true;

            if (!GetTokenInformation(identity.Token, TokenElevationClass, out var elevation, Marshal.SizeOf<TokenElevation>(), out _))
                return false;
            if (elevation.Value == 0)
                return false;

            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ImpersonateNamedPipeClient(SafePipeHandle hNamedPipe);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();

    private const int TokenElevationClass = 20;

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenElevation
    {
        public int Value;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int informationClass,
        out TokenElevation elevation,
        int length,
        out int returned);
}
