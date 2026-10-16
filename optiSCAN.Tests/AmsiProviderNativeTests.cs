// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace optiSCAN.Tests;

/// <summary>
/// Fournisseur AMSI natif, chargé comme le ferait Windows : fabrique COM, nom affiché, analyse
/// d'un flux. Sans hôte de protection joignable, le contenu doit passer vite (fail-open).
/// S'exécute quand la DLL a été compilée (scripts/build-amsi.ps1).
/// </summary>
public sealed class AmsiProviderNativeTests
{
    private static readonly Guid Clsid = new("A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B");
    private const int AmsiResultNotDetected = 1;
    private const int AttributeAppName = 0;
    private const int AttributeContentSize = 2;

    [ComImport, Guid("00000001-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IClassFactory
    {
        [PreserveSig] int CreateInstance(IntPtr outer, ref Guid iid, out IntPtr instance);
        [PreserveSig] int LockServer([MarshalAs(UnmanagedType.Bool)] bool fLock);
    }

    [ComImport, ComVisible(true), Guid("3e47f2e5-81d4-4d3b-897f-545096770373"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAmsiStream
    {
        [PreserveSig] int GetAttribute(int attribute, uint dataSize, IntPtr data, out uint retData);
        [PreserveSig] int Read(ulong position, uint size, IntPtr buffer, out uint readSize);
    }

    [ComImport, Guid("b2cabfe3-fe04-42b1-a5df-08d483d4d125"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAntimalwareProvider
    {
        [PreserveSig] int Scan(IAmsiStream stream, out int result);
        [PreserveSig] void CloseSession(ulong session);
        [PreserveSig] int DisplayName(out IntPtr displayName);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DllGetClassObjectFn(ref Guid clsid, ref Guid iid, out IntPtr factory);

    [ComVisible(true)]
    public sealed class BufferStream : IAmsiStream
    {
        private readonly byte[] _content;
        private readonly string _appName;

        public BufferStream(byte[] content, string appName)
        {
            _content = content;
            _appName = appName;
        }

        public int GetAttribute(int attribute, uint dataSize, IntPtr data, out uint retData)
        {
            byte[] value;
            if (attribute == AttributeContentSize)
                value = BitConverter.GetBytes((ulong)_content.Length);
            else if (attribute == AttributeAppName)
                value = Encoding.Unicode.GetBytes(_appName + "\0");
            else
            {
                retData = 0;
                return unchecked((int)0x80070057); // E_INVALIDARG
            }

            retData = (uint)value.Length;
            if (dataSize < value.Length)
                return unchecked((int)0x8007007A); // E_NOT_SUFFICIENT_BUFFER
            Marshal.Copy(value, 0, data, value.Length);
            return 0;
        }

        public int Read(ulong position, uint size, IntPtr buffer, out uint readSize)
        {
            var available = Math.Max(0, _content.Length - (int)position);
            var count = (int)Math.Min(size, (uint)available);
            Marshal.Copy(_content, (int)position, buffer, count);
            readSize = (uint)count;
            return 0;
        }
    }

    private static string? FindDll()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
        {
            var candidate = Path.Combine(dir, "native", "optiSCAN.AmsiProvider", "x64", "Release", "optiSCAN.AmsiProvider.dll");
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }

    [Fact]
    public void Provider_loads_answers_and_fails_open_without_the_service()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            return;
        var dll = FindDll();
        if (dll == null)
            return; // DLL non compilée sur ce poste (Visual Studio C++ absent) : la CI l'exige.

        var module = NativeLibrary.Load(dll);
        var getClassObject = Marshal.GetDelegateForFunctionPointer<DllGetClassObjectFn>(
            NativeLibrary.GetExport(module, "DllGetClassObject"));

        var clsid = Clsid;
        var iidFactory = typeof(IClassFactory).GUID;
        Assert.Equal(0, getClassObject(ref clsid, ref iidFactory, out var factoryPtr));
        var factory = (IClassFactory)Marshal.GetObjectForIUnknown(factoryPtr);
        Marshal.Release(factoryPtr);

        var iidProvider = typeof(IAntimalwareProvider).GUID;
        Assert.Equal(0, factory.CreateInstance(IntPtr.Zero, ref iidProvider, out var providerPtr));
        var provider = (IAntimalwareProvider)Marshal.GetObjectForIUnknown(providerPtr);
        Marshal.Release(providerPtr);

        Assert.Equal(0, provider.DisplayName(out var namePtr));
        var name = Marshal.PtrToStringUni(namePtr);
        Marshal.FreeCoTaskMem(namePtr);
        Assert.Equal("optiSCAN", name);

        // Le tube de protection n'appartient pas à ce processus de test : soit il n'existe pas,
        // soit c'est le vrai service. Dans les deux cas, un script anodin est « non détecté ».
        var watch = Stopwatch.StartNew();
        Assert.Equal(0, provider.Scan(new BufferStream(Encoding.UTF8.GetBytes("Write-Output 'bonjour'"), "PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_10.0"), out var result));
        watch.Stop();
        Assert.Equal(AmsiResultNotDetected, result);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), "AMSI ne doit pas bloquer : " + watch.Elapsed);

        // Flux vide : rien à analyser, réponse immédiate.
        Assert.Equal(0, provider.Scan(new BufferStream(Array.Empty<byte>(), "test"), out var empty));
        Assert.Equal(AmsiResultNotDetected, empty);
        provider.CloseSession(1);
    }
}
