using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Platform;

/// <summary>
/// Vérifie que le serveur du pipe est ce processus, ou l'hôte du service optiSCAN.
/// <para>
/// Le nom et le dossier de l'exécutable ne suffisent pas : en installation portable, le
/// dossier est inscriptible par l'utilisateur, qui pourrait y lancer un faux « optiSCAN.exe »
/// pour occuper le nom du pipe et répondre « propre » à chaque scan. Le serveur doit donc
/// être le processus du service optiSCAN ou l'hôte qu'il a lancé (PID du service donné par le
/// gestionnaire de services, PID parent de l'hôte), en <b>session 0</b>. La session seule ne
/// suffit pas : une tâche planifiée non interactive d'un utilisateur y tourne aussi. Le vrai
/// serveur est <c>optiSCAN.exe --service-host</c>, lancé par le service Windows sous SYSTEM.
/// </para>
/// </summary>
public static class PipeServerTrust
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    /// <summary>Session des services Windows.</summary>
    internal const uint ServicesSessionId = 0;

    public static bool IsTrusted(SafePipeHandle clientHandle)
    {
        if (!GetNamedPipeServerProcessId(clientHandle, out var pid))
            return false;

        if (pid == (uint)Environment.ProcessId)
            return true;

        if (!GetNamedPipeServerSessionId(clientHandle, out var session) || session != ServicesSessionId)
            return false;

        var image = QueryImagePath(pid);
        if (string.IsNullOrWhiteSpace(image))
            return false;

        var name = Path.GetFileName(image);
        // Serveur du tube : l'hôte console (3.1) ou le service. L'interface optiSCAN.exe ne
        // sert plus le tube depuis la session 0.
        if (!name.Equals("optiSCAN.Host.exe", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("optiSCAN.Service.exe", StringComparison.OrdinalIgnoreCase))
            return false;

        var dir = Path.GetFullPath(Path.GetDirectoryName(image) ?? string.Empty);
        var inAllowedDirectory = false;
        foreach (var allowed in AllowedDirectories())
        {
            if (string.Equals(dir, allowed, StringComparison.OrdinalIgnoreCase))
            {
                inAllowedDirectory = true;
                break;
            }
        }

        // La session 0 ne prouve pas l'identité : une tâche planifiée « exécuter même si
        // l'utilisateur n'est pas connecté » y tourne aussi, sous le compte de l'utilisateur.
        // Le serveur doit être le processus du service optiSCAN, ou l'hôte qu'il a lancé.
        return inAllowedDirectory && IsProtectionServiceProcess(pid);
    }

    /// <summary>
    /// Vrai si <paramref name="pid"/> est le processus du service <see cref="ProtectionIdentifiers.ServiceName"/>
    /// (PID donné par le gestionnaire de services) ou l'un de ses enfants directs, créé après lui.
    /// </summary>
    internal static bool IsProtectionServiceProcess(uint pid)
    {
        var servicePid = QueryServiceProcessId(ProtectionIdentifiers.ServiceName);
        if (servicePid == 0)
            return false;
        if (pid == servicePid)
            return true;
        if (!TryGetParentProcessId(pid, out var parent) || parent != servicePid)
            return false;

        // Un PID réutilisé : un processus plus ancien que le service ne peut pas être son enfant.
        if (TryGetCreationTime(pid, out var childCreated) && TryGetCreationTime(servicePid, out var serviceCreated))
            return childCreated >= serviceCreated;
        return true;
    }

    private static uint QueryServiceProcessId(string serviceName)
    {
        const uint ScManagerConnect = 0x0001;
        const uint ServiceQueryStatus = 0x0004;
        const int ScStatusProcessInfo = 0;

        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero)
            return 0;
        try
        {
            var service = OpenService(scm, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
                return 0;
            try
            {
                var buffer = new byte[Marshal.SizeOf<ServiceStatusProcess>()];
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, buffer, buffer.Length, out _))
                    return 0;
                var status = MemoryMarshal.Read<ServiceStatusProcess>(buffer);
                const uint ServiceRunning = 4;
                return status.CurrentState == ServiceRunning ? status.ProcessId : 0;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    private static bool TryGetParentProcessId(uint pid, out uint parent)
    {
        const uint Th32csSnapProcess = 0x00000002;
        parent = 0;
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            return false;
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
                return false;
            do
            {
                if (entry.ProcessId == pid)
                {
                    parent = entry.ParentProcessId;
                    return true;
                }
            }
            while (Process32Next(snapshot, ref entry));
            return false;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    private static bool TryGetCreationTime(uint pid, out long creation)
    {
        creation = 0;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
            return false;
        try
        {
            return GetProcessTimes(handle, out creation, out _, out _, out _);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")]
    private static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, byte[] buffer, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    private static IEnumerable<string> AllowedDirectories()
    {
        yield return Path.GetFullPath(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles))
            yield return Path.GetFullPath(Path.Combine(programFiles, "optiSCAN"));
    }

    private static string? QueryImagePath(uint pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
            return null;

        try
        {
            var capacity = 1024;
            var buffer = new char[capacity];
            if (!QueryFullProcessImageName(handle, 0, buffer, ref capacity))
                return null;
            return new string(buffer, 0, capacity);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerSessionId(SafePipeHandle pipe, out uint serverSessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, [Out] char[] name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
