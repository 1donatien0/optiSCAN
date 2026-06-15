#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <string>
#include <vector>
#include "pipe_client.h"

// GUID : {A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}
static const CLSID CLSID_OptiscanAmsiProvider =
{ 0xa8f4e2b1, 0x9c3d, 0x4e5f, { 0x8a, 0x7b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b } };

class OptiscanAmsiProvider final : public IAntimalwareProvider
{
    LONG _ref = 1;

public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider))
        {
            *ppv = static_cast<IAntimalwareProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_ref); }
    STDMETHODIMP_(ULONG) Release() override
    {
        const ULONG r = InterlockedDecrement(&_ref);
        if (r == 0) delete this;
        return r;
    }

    STDMETHODIMP Scan(
        IAmsiStream* stream,
        AMSI_RESULT* result) override
    {
        if (!stream || !result)
            return E_POINTER;

        *result = AMSI_RESULT_CLEAN;

        ULONGLONG size = 0;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, &size)) || size == 0 || size > 4 * 1024 * 1024)
            return S_OK;

        std::vector<BYTE> data(static_cast<size_t>(size));
        ULONG read = 0;
        if (FAILED(stream->Read(data.data(), static_cast<ULONG>(data.size()), &read)) || read == 0)
            return S_OK;

        // Encodage base64 minimal (stub — production : utiliser CryptBinaryToString)
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string b64data;
        b64data.reserve((read + 2) / 3 * 4);
        for (ULONG i = 0; i < read; i += 3)
        {
            const unsigned a = data[i];
            const unsigned b = (i + 1 < read) ? data[i + 1] : 0;
            const unsigned c = (i + 2 < read) ? data[i + 2] : 0;
            b64data.push_back(b64[(a >> 2) & 0x3F]);
            b64data.push_back(b64[((a & 0x3) << 4) | ((b >> 4) & 0xF)]);
            b64data.push_back((i + 1 < read) ? b64[((b & 0xF) << 2) | ((c >> 6) & 0x3)] : '=');
            b64data.push_back((i + 2 < read) ? b64[c & 0x3F] : '=');
        }

        const std::string request = std::string(R"({"op":"scan_buffer","buffer_b64":")") + b64data + R"(","content_name":"amsi_buffer"})";
        std::string response;
        if (!optiscan::ipc::ScanBufferViaPipe(L"\\\\.\\pipe\\optiSCAN_Protection_v8", request, response))
            return S_OK;

        if (response.find("\"clean\":false") != std::string::npos)
            *result = AMSI_RESULT_DETECTED;

        return S_OK;
    }

    STDMETHODIMP CloseSession() override { return S_OK; }
};

class OptiscanClassFactory final : public IClassFactory
{
    LONG _ref = 1;

public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_ref); }
    STDMETHODIMP_(ULONG) Release() override
    {
        const ULONG r = InterlockedDecrement(&_ref);
        if (r == 0) delete this;
        return r;
    }

    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* provider = new (std::nothrow) OptiscanAmsiProvider();
        if (!provider) return E_OUTOFMEMORY;
        const HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL lock) override
    {
        if (lock) InterlockedIncrement(&g_lockCount);
        else InterlockedDecrement(&g_lockCount);
        return S_OK;
    }

    static LONG g_lockCount;
};

LONG OptiscanClassFactory::g_lockCount = 0;

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(GetModuleHandleW(nullptr));
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (!IsEqualCLSID(rclsid, CLSID_OptiscanAmsiProvider))
        return CLASS_E_CLASSNOTAVAILABLE;

    auto* factory = new (std::nothrow) OptiscanClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return OptiscanClassFactory::g_lockCount == 0 ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer()
{
    return S_OK;
}

STDAPI DllUnregisterServer()
{
    return S_OK;
}
