// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Services;

/// <summary>
/// Lancement des analyseurs en ligne de commande (<c>yara</c>, <c>yarac</c>, <c>clamscan</c>)
/// dans l'AppContainer de clamd, sans capacité réseau.
/// </summary>
/// <remarks>
/// Sous SYSTEM, ces outils lisent des contenus fournis par n'importe quel compte. Une faille
/// d'analyseur (YARA 4.5.5 n'a pas les corrections de bornes de 4.5.6 à 4.5.8) y donnait une
/// exécution de code SYSTEM. Dans le conteneur, le processus n'a que les droits accordés au SID
/// du conteneur : lecture des dossiers d'analyse et écriture dans un dossier de travail. Il
/// partage la frontière déjà admise pour clamd (même SID, que la normalisation de ProgramData
/// reconnaît), sans le réseau. Un objet job propre interdit tout processus enfant et termine
/// l'analyseur sur une exception non gérée, en plus de l'objet job de durée de vie de l'hôte.
/// </remarks>
internal static partial class ClamdIsolation
{
    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    private const uint HandleFlagInherit = 0x00000001;

    /// <summary>Processus analyseur confiné, avec ses sorties redirigées.</summary>
    internal sealed class ContainedScanner : IDisposable
    {
        internal ContainedScanner(SafeProcessHandle process, int processId, SafeFileHandle output, SafeFileHandle error, SafeWaitHandle job)
        {
            Process = process;
            ProcessId = processId;
            Output = output;
            Error = error;
            Job = job;
        }

        internal SafeProcessHandle Process { get; }
        internal int ProcessId { get; }
        internal SafeFileHandle Output { get; }
        internal SafeFileHandle Error { get; }

        /// <summary>Objet job « tuer à la fermeture » propre à ce lancement.</summary>
        internal SafeWaitHandle Job { get; }

        internal bool TryGetExitCode(out int exitCode)
        {
            exitCode = -1;
            if (!GetExitCodeProcess(Process.DangerousGetHandle(), out var code))
                return false;
            if (code == StillActive)
                return false;
            exitCode = code;
            return true;
        }

        internal void Terminate()
        {
            if (!Process.IsInvalid && !Process.IsClosed)
                TerminateProcess(Process.DangerousGetHandle(), 1);
        }

        public void Dispose()
        {
            // Fermer le job termine l'analyseur s'il tourne encore.
            Job.Dispose();
            Output.Dispose();
            Error.Dispose();
            Process.Dispose();
        }
    }

    private const int StillActive = 259;

    /// <summary>
    /// Lance <paramref name="exe"/> dans le conteneur. Les dossiers en lecture et en écriture
    /// reçoivent l'ACE héritable du conteneur ; un échec d'ACL ou de lancement lève une
    /// exception (l'appelant ne doit pas se replier sur un lancement non confiné).
    /// </summary>
    internal static ContainedScanner StartScanner(
        string exe,
        string commandLine,
        string workingDirectory,
        IReadOnlyList<string> readableDirectories,
        IReadOnlyList<string> writableDirectories)
    {
        if (!File.Exists(exe))
            throw new FileNotFoundException("Analyseur introuvable.", exe);

        var exeDir = Path.GetDirectoryName(exe);
        if (string.IsNullOrEmpty(exeDir))
            throw new InvalidOperationException("Dossier de l'analyseur invalide.");
        if (!TryGrant(exeDir, readOnly: true)
            && !IsWindowsDirectory(exeDir)
            && !IsProgramFilesDirectory(exeDir))
            throw new UnauthorizedAccessException("Lecture de l'analyseur refusée au conteneur.");

        foreach (var dir in readableDirectories)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                continue;
            if (!TryGrant(dir, readOnly: true))
                throw new UnauthorizedAccessException("ACL de lecture du conteneur refusée.");
        }

        foreach (var dir in writableDirectories)
        {
            Directory.CreateDirectory(dir);
            if (!TryGrant(dir, readOnly: false))
                throw new UnauthorizedAccessException("ACL d'écriture du conteneur refusée.");
        }

        if (!TryGetContainerSid(out var containerSid))
            throw new InvalidOperationException("Profil AppContainer indisponible.");

        SafeFileHandle? outRead = null, errRead = null;
        IntPtr outWrite = IntPtr.Zero, errWrite = IntPtr.Zero;
        SafeWaitHandle? job = null;
        try
        {
            CreateInheritablePipe(out outRead, out outWrite);
            CreateInheritablePipe(out errRead, out errWrite);
            job = CreateScannerJob();

            var info = CreateContained(
                exe,
                commandLine,
                workingDirectory,
                containerSid,
                Array.Empty<IntPtr>(),
                (outWrite, errWrite),
                job.DangerousGetHandle());

            var result = new ContainedScanner(
                new SafeProcessHandle(info.Process, ownsHandle: true),
                info.ProcessId,
                outRead,
                errRead,
                job);
            outRead = null;
            errRead = null;
            job = null;
            return result;
        }
        finally
        {
            // Les extrémités d'écriture ne restent que chez l'enfant : la lecture voit la fin
            // de flux quand il se termine.
            if (outWrite != IntPtr.Zero)
                CloseHandle(outWrite);
            if (errWrite != IntPtr.Zero)
                CloseHandle(errWrite);
            outRead?.Dispose();
            errRead?.Dispose();
            job?.Dispose();
            FreeSid(containerSid);
        }
    }

    private static void CreateInheritablePipe(out SafeFileHandle read, out IntPtr write)
    {
        var attributes = new SecurityAttributes
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true,
        };
        if (!CreatePipe(out var readHandle, out write, ref attributes, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        // Seule l'extrémité d'écriture est héritée par l'enfant.
        if (!SetHandleInformation(readHandle, HandleFlagInherit, 0))
        {
            var error = Marshal.GetLastWin32Error();
            CloseHandle(readHandle);
            CloseHandle(write);
            write = IntPtr.Zero;
            throw new Win32Exception(error);
        }
        read = new SafeFileHandle(readHandle, ownsHandle: true);
    }

    private static SafeWaitHandle CreateScannerJob()
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose
                    | JobObjectLimitActiveProcess
                    | JobObjectLimitDieOnUnhandledException,
                ActiveProcessLimit = 1,
            },
        };
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref limits,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            var error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error);
        }

        return new SafeWaitHandle(job, ownsHandle: true);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SecurityAttributes attributes, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
}
