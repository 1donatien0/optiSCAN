// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace optiSCAN.Services;

/// <summary>
/// Lance clamd dans un AppContainer. Le conteneur limite l'accès aux fichiers;
/// le TCP clamd reste un socket non authentifié, lié à la boucle locale par
/// clamd.conf. Son accessibilité locale dépend des filtres AppContainer/loopback
/// de Windows; les clients optiSCAN passent par le tube nommé avec ACL.
/// </summary>
internal static partial class ClamdIsolation
{
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateSuspended = 0x00000004;
    private const int ProcThreadAttributeSecurityCapabilities = 0x00020009;
    private const int AlreadyExists = unchecked((int)0x800700B7);
    private const uint SeGroupEnabled = 0x00000004;
    private const int ProcThreadAttributeHandleList = 0x00020002;
    private const int StartfUseStdHandles = 0x00000100;
    private static readonly Dictionary<int, IntPtr> ProcessHandles = new();

    internal static Process? Start(
        string exe,
        string arguments,
        string workingDirectory,
        bool network,
        IReadOnlyList<string> writableDirectories)
    {
        if (!File.Exists(exe))
            return null;

        var exeDir = Path.GetDirectoryName(exe);
        if (string.IsNullOrEmpty(exeDir))
            return null;
        // Program Files et Windows accordent déjà la lecture à ALL APPLICATION PACKAGES
        // par héritage : un compte standard ne peut pas y ajouter d'ACE, et n'en a pas besoin.
        // Ailleurs (build de développement, dossier portable), l'ACE est indispensable.
        if (!TryGrant(exeDir, readOnly: true)
            && !IsWindowsDirectory(exeDir)
            && !IsProgramFilesDirectory(exeDir))
            return null;

        foreach (var dir in writableDirectories)
        {
            try { Directory.CreateDirectory(dir); }
            catch (Exception ignored) when (!ignored.IsFatal()) { return null; }
            if (!TryGrant(dir, readOnly: false))
                return null;
        }

        if (!TryGetContainerSid(out var containerSid))
            return null;

        var capabilities = network ? BuildNetworkCapabilities() : Array.Empty<IntPtr>();
        try
        {
            return StartInContainer(exe, arguments, workingDirectory, containerSid, capabilities);
        }
        finally
        {
            foreach (var cap in capabilities)
                LocalFree(cap);
            FreeSid(containerSid);
        }
    }

    private static Process? StartInContainer(
        string exe,
        string arguments,
        string workingDirectory,
        IntPtr containerSid,
        IReadOnlyList<IntPtr> capabilitySids)
    {
        var line = "\"" + exe + "\"" + (string.IsNullOrWhiteSpace(arguments) ? string.Empty : " " + arguments);
        try
        {
            var info = CreateContained(exe, line, workingDirectory, containerSid, capabilitySids, stdio: null, ownJob: IntPtr.Zero);
            lock (ProcessHandles)
                ProcessHandles[info.ProcessId] = info.Process;
            return Process.GetProcessById(info.ProcessId);
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ClamdIsolation", "Lancement isolé refusé", ex);
            return null;
        }
    }

    /// <summary>
    /// Crée le processus dans le conteneur, suspendu, le rattache à la durée de vie de l'hôte
    /// (et à <paramref name="ownJob"/> s'il est fourni), puis le reprend. Rend la poignée du
    /// processus, ouverte ; celle du fil est fermée.
    /// </summary>
    /// <param name="stdio">
    /// Sorties standard et d'erreur à transmettre. Seules ces deux poignées sont héritées
    /// (<c>PROC_THREAD_ATTRIBUTE_HANDLE_LIST</c>) : le service tient des poignées héritables
    /// (tubes, fichiers) qu'un analyseur compromis ne doit pas recevoir.
    /// </param>
    private static ProcessInformation CreateContained(
        string exe,
        string commandLine,
        string workingDirectory,
        IntPtr containerSid,
        IReadOnlyList<IntPtr> capabilitySids,
        (IntPtr Output, IntPtr Error)? stdio,
        IntPtr ownJob)
    {
        var capArray = IntPtr.Zero;
        var capStruct = IntPtr.Zero;
        var attributeList = IntPtr.Zero;
        var handleList = IntPtr.Zero;
        try
        {
            if (capabilitySids.Count > 0)
            {
                var itemSize = Marshal.SizeOf<SidAndAttributes>();
                capArray = Marshal.AllocHGlobal(itemSize * capabilitySids.Count);
                for (var i = 0; i < capabilitySids.Count; i++)
                {
                    var item = new SidAndAttributes { Sid = capabilitySids[i], Attributes = SeGroupEnabled };
                    Marshal.StructureToPtr(item, capArray + (i * itemSize), false);
                }
            }

            var caps = new SecurityCapabilities
            {
                AppContainerSid = containerSid,
                Capabilities = capArray,
                CapabilityCount = (uint)capabilitySids.Count,
            };
            capStruct = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(caps, capStruct, false);

            var attributeCount = stdio.HasValue ? 2 : 1;
            var size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, 0, ref size);
            attributeList = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attributeList, attributeCount, 0, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    (IntPtr)ProcThreadAttributeSecurityCapabilities,
                    capStruct,
                    (IntPtr)Marshal.SizeOf<SecurityCapabilities>(),
                    IntPtr.Zero,
                    IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var startup = new StartupInfoEx { StartupInfo = { cb = Marshal.SizeOf<StartupInfoEx>() }, AttributeList = attributeList };
            if (stdio is { } handles)
            {
                handleList = Marshal.AllocHGlobal(IntPtr.Size * 2);
                Marshal.WriteIntPtr(handleList, 0, handles.Output);
                Marshal.WriteIntPtr(handleList, IntPtr.Size, handles.Error);
                if (!UpdateProcThreadAttribute(
                        attributeList,
                        0,
                        (IntPtr)ProcThreadAttributeHandleList,
                        handleList,
                        (IntPtr)(IntPtr.Size * 2),
                        IntPtr.Zero,
                        IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                startup.StartupInfo.Flags = StartfUseStdHandles;
                startup.StartupInfo.StdInput = IntPtr.Zero;
                startup.StartupInfo.StdOutput = handles.Output;
                startup.StartupInfo.StdError = handles.Error;
            }

            // CreateProcessW peut écrire dans la ligne de commande : tampon modifiable, terminé par NUL.
            var command = new char[commandLine.Length + 1];
            commandLine.CopyTo(0, command, 0, commandLine.Length);

            if (!CreateProcess(
                    exe,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    stdio.HasValue,
                    // Suspendu : rattaché à l'objet job avant d'exécuter la moindre instruction.
                    ExtendedStartupInfoPresent | CreateNoWindow | CreateSuspended,
                    IntPtr.Zero,
                    workingDirectory,
                    ref startup,
                    out var info))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                AttachToHostLifetime(info.Process);
                if (ownJob != IntPtr.Zero && !AssignProcessToJobObject(ownJob, info.Process))
                {
                    var error = Marshal.GetLastWin32Error();
                    TerminateProcess(info.Process, 1);
                    CloseHandle(info.Process);
                    throw new Win32Exception(error);
                }
                if (ResumeThread(info.Thread) == uint.MaxValue)
                {
                    var error = Marshal.GetLastWin32Error();
                    TerminateProcess(info.Process, 1);
                    CloseHandle(info.Process);
                    throw new Win32Exception(error);
                }
            }
            finally
            {
                CloseHandle(info.Thread);
            }

            return info;
        }
        finally
        {
            if (attributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (handleList != IntPtr.Zero)
                Marshal.FreeHGlobal(handleList);
            if (capStruct != IntPtr.Zero)
                Marshal.FreeHGlobal(capStruct);
            if (capArray != IntPtr.Zero)
                Marshal.FreeHGlobal(capArray);
        }
    }

    internal static void Release(Process? process)
    {
        if (process == null)
            return;
        lock (ProcessHandles)
        {
            if (!ProcessHandles.Remove(process.Id, out var handle))
                return;
            CloseHandle(handle);
        }
    }

    internal static bool TryDuplicateInto(Process target, IntPtr source, out IntPtr remote)
    {
        remote = IntPtr.Zero;
        IntPtr process;
        var owned = false;
        lock (ProcessHandles)
        {
            if (!ProcessHandles.TryGetValue(target.Id, out process))
            {
                process = OpenProcess(0x0040, false, target.Id);
                owned = process != IntPtr.Zero;
            }
        }
        if (process == IntPtr.Zero)
        {
            AppLogger.Warn("ClamdIsolation", "Ouverture du relais refusée (" + Marshal.GetLastWin32Error().ToString() + ")");
            return false;
        }
        try
        {
            if (DuplicateHandle(new IntPtr(-1), source, process, out remote, 0, false, 2))
                return true;
            AppLogger.Warn("ClamdIsolation", "Duplication de handle refusée (" + Marshal.GetLastWin32Error().ToString() + ")");
            return false;
        }
        finally
        {
            if (owned)
                CloseHandle(process);
        }
    }

    internal static SecurityIdentifier? ContainerSid()
    {
        if (!TryGetContainerSid(out var sid))
            return null;
        try
        {
            return new SecurityIdentifier(sid);
        }
        finally
        {
            FreeSid(sid);
        }
    }

    internal static int ReadExitCode(Process process)
    {
        const uint QueryLimited = 0x1000;
        var handle = OpenProcess(QueryLimited, false, process.Id);
        if (handle == IntPtr.Zero)
            return -1;
        try
        {
            return GetExitCodeProcess(handle, out var code) ? code : -1;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    internal static bool IsInAppContainer(Process process)
    {
        const uint QueryInformation = 0x0400;
        const uint TokenQuery = 0x0008;
        const int TokenAppContainerSid = 29;
        var handle = OpenProcess(QueryInformation, false, process.Id);
        if (handle == IntPtr.Zero)
            return false;
        try
        {
            if (!OpenProcessToken(handle, TokenQuery, out var token))
                return false;
            try
            {
                GetTokenInformation(token, TokenAppContainerSid, IntPtr.Zero, 0, out var needed);
                if (needed <= 0)
                    return false;
                var buffer = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!GetTokenInformation(token, TokenAppContainerSid, buffer, needed, out _))
                        return false;
                    var sid = Marshal.ReadIntPtr(buffer);
                    return sid != IntPtr.Zero && !IsWellKnownSid(sid, 0);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static bool IsWindowsDirectory(string directory)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows))
            return false;
        var root = Path.GetFullPath(windows.TrimEnd(Path.DirectorySeparatorChar));
        var full = Path.GetFullPath(directory);
        return full.Equals(root, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsProgramFilesDirectory(string directory)
    {
        var full = Path.GetFullPath(directory);
        foreach (var root in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 })
        {
            if (string.IsNullOrEmpty(root))
                continue;
            var normalized = Path.GetFullPath(root.TrimEnd(Path.DirectorySeparatorChar));
            if (full.StartsWith(normalized + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    internal static bool TryGrantFile(string path)
    {
        try
        {
            if (!TryGetContainerSid(out var sidPtr))
                return false;
            try
            {
                var sid = new SecurityIdentifier(sidPtr);
                var info = new FileInfo(path);
                var security = info.GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(
                    sid,
                    FileSystemRights.Modify | FileSystemRights.Delete,
                    AccessControlType.Allow));
                info.SetAccessControl(security);
                return true;
            }
            finally
            {
                FreeSid(sidPtr);
            }
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ClamdIsolation", "ACL du conteneur refusée sur " + path, ex);
            return false;
        }
    }

    internal static bool TryGrant(string directory, bool readOnly)
    {
        try
        {
            if (!TryGetContainerSid(out var sidPtr))
                return false;
            try
            {
                var sid = new SecurityIdentifier(sidPtr);
                var rights = readOnly
                    ? FileSystemRights.ReadAndExecute
                    : FileSystemRights.Modify | FileSystemRights.DeleteSubdirectoriesAndFiles;
                var info = new DirectoryInfo(directory);
                var security = info.GetAccessControl();
                if (HasInheritableAce(security, sid, rights))
                    return true;

                // Écrire la DACL d'un dossier repropage l'héritage à tout son contenu :
                // seulement sur nos propres dossiers, et une seule fois.
                security.AddAccessRule(new FileSystemAccessRule(
                    sid,
                    rights,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                info.SetAccessControl(security);
                return true;
            }
            finally
            {
                FreeSid(sidPtr);
            }
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ClamdIsolation", "ACL du conteneur refusée sur " + directory, ex);
            return false;
        }
    }

    private static bool HasInheritableAce(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights)
    {
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && sid.Equals(rule.IdentityReference)
                && (rule.FileSystemRights & rights) == rights
                && rule.InheritanceFlags.HasFlag(InheritanceFlags.ContainerInherit)
                && rule.InheritanceFlags.HasFlag(InheritanceFlags.ObjectInherit))
                return true;
        }

        return false;
    }

    private static bool TryGetContainerSid(out IntPtr sid)
    {
        sid = IntPtr.Zero;
        // Nom aléatoire par installation : voir ClamdContainerName.
        var containerName = optiSCAN.Platform.ClamdContainerName.Current();
        if (containerName == null)
        {
            AppLogger.Warn("ClamdIsolation", "Nom du conteneur clamd indisponible");
            return false;
        }

        var hr = CreateAppContainerProfile(containerName, containerName, "clamd optiSCAN", IntPtr.Zero, 0, out sid);
        if (hr == AlreadyExists)
            hr = DeriveAppContainerSidFromAppContainerName(containerName, out sid);
        if (hr != 0 || sid == IntPtr.Zero)
        {
            AppLogger.Warn("ClamdIsolation", "Profil AppContainer indisponible (" + hr.ToString("X8") + ")");
            return false;
        }
        return true;
    }

    private static IntPtr[] BuildNetworkCapabilities()
    {
        // Écoute et boucle locale à l'intérieur du conteneur.
        var ids = new[] { "S-1-15-3-2", "S-1-15-3-3" };
        var list = new List<IntPtr>();
        foreach (var id in ids)
        {
            if (ConvertStringSidToSid(id, out var sid))
                list.Add(sid);
        }
        return list.ToArray();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityCapabilities
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, Reserved2;
        public IntPtr Reserved2Ptr, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int CreateAppContainerProfile(
        string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSidToSid(string sid, out IntPtr result);

    /// <summary>
    /// Objet job « tuer à la fermeture » propre à ce processus. Sa poignée n'est jamais fermée
    /// explicitement : Windows la ferme quand l'hôte se termine, même sur un plantage ou un
    /// <c>Kill</c>, et termine alors clamd et son relais. Sans lui, clamd survivait à l'hôte ;
    /// l'hôte suivant se reconnectait à un tube que plus personne ne servait (voir Z7).
    /// </summary>
    private static readonly Lazy<IntPtr> HostLifetimeJob = new(CreateKillOnCloseJob);

    private static IntPtr CreateKillOnCloseJob()
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            AppLogger.Warn("ClamdIsolation", $"Objet job indisponible (erreur {Marshal.GetLastWin32Error()}) : clamd pourra survivre à l'hôte.");
            return IntPtr.Zero;
        }

        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation { LimitFlags = JobObjectLimitKillOnJobClose },
        };
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref limits,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            AppLogger.Warn("ClamdIsolation", $"Limite « tuer à la fermeture » refusée (erreur {Marshal.GetLastWin32Error()}).");
            CloseHandle(job);
            return IntPtr.Zero;
        }

        return job;
    }

    /// <summary>Rattache un processus lancé (encore suspendu) à la durée de vie de l'hôte.</summary>
    private static void AttachToHostLifetime(IntPtr process)
    {
        var job = HostLifetimeJob.Value;
        if (job == IntPtr.Zero)
            return;
        if (!AssignProcessToJobObject(job, process))
            AppLogger.Warn("ClamdIsolation", $"Rattachement à l'objet job refusé (erreur {Marshal.GetLastWin32Error()}) : clamd pourra survivre à l'hôte.");
    }

    internal const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformationClass = 9;

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateJobObjectW")]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int infoClass, ref JobObjectExtendedLimitInformation info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string applicationName,
        char[] commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startup,
        out ProcessInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int @class, IntPtr buffer, int length, out int returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool IsWellKnownSid(IntPtr sid, int wellKnown);
}
