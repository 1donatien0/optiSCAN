// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace optiSCAN.Services;

/// <summary>
/// Vérifie qu'un serveur de tube nommé tourne sous le même compte que ce processus.
/// </summary>
/// <remarks>
/// Les tubes de clamd portent un nom aléatoire, mais la liste des tubes (<c>\\.\pipe\</c>) est
/// lisible par tout compte. Quand le relais disparaît (hôte arrêté ou planté) alors que clamd
/// survit, le nom reste écrit dans <c>clamd.pipe</c> et l'hôte suivant s'y reconnecte : un autre
/// compte qui a recréé ce nom recevait alors le contenu des fichiers analysés et pouvait répondre
/// « propre ». Le client exige donc un serveur du même compte, et ne se laisse jamais usurper.
/// </remarks>
internal static class PipeServerAccount
{
    /// <summary>Niveau d'usurpation accordé au serveur : identification seulement.</summary>
    internal const TokenImpersonationLevel ClientImpersonation = TokenImpersonationLevel.Identification;

    internal static bool IsSameAccount(NamedPipeClientStream pipe)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid))
                return false;
            if (pid == (uint)Environment.ProcessId)
                return true;

            using var current = WindowsIdentity.GetCurrent();
            var expected = current.User;
            if (expected == null)
                return false;

            const uint QueryLimitedInformation = 0x1000;
            const uint TokenQuery = 0x0008;
            var process = OpenProcess(QueryLimitedInformation, false, pid);
            if (process == IntPtr.Zero)
                return false;
            try
            {
                if (!OpenProcessToken(process, TokenQuery, out var token))
                    return false;
                try
                {
                    using var server = new WindowsIdentity(token);
                    return server.User is { } user && expected.Equals(user);
                }
                finally
                {
                    CloseHandle(token);
                }
            }
            finally
            {
                CloseHandle(process);
            }
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
