// SPDX-License-Identifier: GPL-3.0-or-later
// optiSCAN — fournisseur AMSI (Antimalware Scan Interface).
//
// Windows appelle ce fournisseur, dans le processus de l'application (PowerShell, hôte de
// scripts, macros Office, .NET...), avant d'exécuter un contenu. Le contenu est transmis à
// l'hôte SYSTEM d'optiSCAN par le tube authentifié (`scan_buffer`), qui l'analyse avec ClamAV
// et YARA dans leur AppContainer.
//
// Règles imposées par le contexte d'exécution (le fournisseur vit dans des processus tiers) :
//   - aucune exception C++ ne sort d'une méthode COM ; un échec rend « propre » (fail-open) :
//     un service arrêté ne doit jamais bloquer PowerShell ;
//   - délais courts et bornés (voir pipe_client.cpp) ;
//   - aucun état global mutable hors compteurs atomiques.

#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <wincrypt.h>
#include <new>
#include <string>
#include <vector>
#include "pipe_client.h"
#include "protection_identifiers.h"

#pragma comment(lib, "crypt32.lib")

namespace
{
    // {A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B} — miroir de PlatformRegistration.AmsiProviderGuid.
    constexpr CLSID kClsid = { 0xa8f4e2b1, 0x9c3d, 0x4e5f, { 0x8a, 0x7b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b } };
    constexpr wchar_t kClsidString[] = L"{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}";
    constexpr wchar_t kDisplayName[] = L"optiSCAN";

    // Plafond du contenu transmis : le cadrage JSON du tube est limité à 1 Mo, le base64
    // ajoute un tiers. Au-delà, seul le début est analysé (les scripts sont en général courts).
    constexpr ULONG kMaxContentBytes = 512 * 1024;

    HMODULE g_module = nullptr;
    LONG g_objects = 0;
    LONG g_locks = 0;

    std::string EncodeBase64(const BYTE* data, DWORD size)
    {
        if (size == 0)
            return {};
        DWORD encodedLen = 0;
        if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encodedLen))
            return {};
        std::string encoded(encodedLen, '\0');
        if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &encodedLen))
            return {};
        while (!encoded.empty() && encoded.back() == '\0')
            encoded.pop_back();
        return encoded;
    }

    std::wstring ReadStringAttribute(IAmsiStream* stream, AMSI_ATTRIBUTE attribute)
    {
        ULONG needed = 0;
        const HRESULT probe = stream->GetAttribute(attribute, 0, nullptr, &needed);
        if (probe != E_NOT_SUFFICIENT_BUFFER || needed == 0 || needed > 64 * 1024)
            return {};
        std::vector<BYTE> buffer(needed + sizeof(wchar_t), 0);
        ULONG written = 0;
        if (FAILED(stream->GetAttribute(attribute, needed, buffer.data(), &written)))
            return {};
        return std::wstring(reinterpret_cast<const wchar_t*>(buffer.data()));
    }

    bool ContainsInsensitive(const std::wstring& haystack, const wchar_t* needle)
    {
        std::wstring h = haystack, n = needle;
        CharLowerBuffW(h.data(), static_cast<DWORD>(h.size()));
        CharLowerBuffW(n.data(), static_cast<DWORD>(n.size()));
        return h.find(n) != std::wstring::npos;
    }

    // Nom de la copie d'analyse côté service : l'extension oriente certaines signatures.
    const char* ContentNameFor(const std::wstring& appName)
    {
        if (ContainsInsensitive(appName, L"powershell"))
            return "amsi_content.ps1";
        if (ContainsInsensitive(appName, L"jscript"))
            return "amsi_content.js";
        if (ContainsInsensitive(appName, L"vbscript"))
            return "amsi_content.vbs";
        if (ContainsInsensitive(appName, L"vba") || ContainsInsensitive(appName, L"office"))
            return "amsi_content.vba";
        if (ContainsInsensitive(appName, L"dotnet") || ContainsInsensitive(appName, L"coreclr"))
            return "amsi_content.bin";
        return "amsi_content.txt";
    }

    // Réponse du service : menace seulement si « ok » est vrai et « clean » faux. Une erreur
    // (service occupé, limite de débit, scan incomplet) rend « propre » : jamais de blocage
    // sur un défaut d'optiSCAN.
    bool IsThreatResponse(const std::string& response)
    {
        return response.find("\"ok\":true") != std::string::npos
            && response.find("\"clean\":false") != std::string::npos;
    }
}

class OptiscanAmsiProvider final : public IAntimalwareProvider
{
    LONG _ref = 1;

public:
    OptiscanAmsiProvider() { InterlockedIncrement(&g_objects); }
    ~OptiscanAmsiProvider() { InterlockedDecrement(&g_objects); }

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;
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
        if (r == 0)
            delete this;
        return r;
    }

    STDMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result) override
    {
        if (!stream || !result)
            return E_INVALIDARG;
        *result = AMSI_RESULT_NOT_DETECTED;

        try
        {
            ULONGLONG size = 0;
            ULONG written = 0;
            if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(size), reinterpret_cast<PUCHAR>(&size), &written))
                || written != sizeof(size) || size == 0)
                return S_OK;

            const ULONG toRead = size > kMaxContentBytes ? kMaxContentBytes : static_cast<ULONG>(size);
            std::vector<BYTE> data(toRead);
            ULONG read = 0;
            if (FAILED(stream->Read(0, toRead, data.data(), &read)) || read == 0)
                return S_OK;

            const std::string b64 = EncodeBase64(data.data(), read);
            if (b64.empty())
                return S_OK;

            const std::wstring appName = ReadStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
            std::string request;
            request.reserve(b64.size() + 128);
            request += R"({"proto":)";
            request += optiscan::ids::kProtocolVersionJson;
            request += R"(,"op":"scan_buffer","buffer_b64":")";
            request += b64;
            request += R"(","content_name":")";
            request += ContentNameFor(appName);
            request += R"("})";

            std::string response;
            if (optiscan::ipc::ScanBufferViaPipe(optiscan::ids::kProtectionPipePath, request, response)
                && IsThreatResponse(response))
                *result = AMSI_RESULT_DETECTED;
        }
        catch (...)
        {
            *result = AMSI_RESULT_NOT_DETECTED;
        }
        return S_OK;
    }

    STDMETHODIMP_(void) CloseSession(ULONGLONG) override {}

    STDMETHODIMP DisplayName(LPWSTR* displayName) override
    {
        if (!displayName)
            return E_POINTER;
        const size_t bytes = sizeof(kDisplayName);
        auto* copy = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (!copy)
            return E_OUTOFMEMORY;
        memcpy(copy, kDisplayName, bytes);
        *displayName = copy;
        return S_OK;
    }
};

class OptiscanClassFactory final : public IClassFactory
{
    LONG _ref = 1;

public:
    OptiscanClassFactory() { InterlockedIncrement(&g_objects); }
    ~OptiscanClassFactory() { InterlockedDecrement(&g_objects); }

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;
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
        if (r == 0)
            delete this;
        return r;
    }

    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;
        *ppv = nullptr;
        if (outer)
            return CLASS_E_NOAGGREGATION;
        auto* provider = new (std::nothrow) OptiscanAmsiProvider();
        if (!provider)
            return E_OUTOFMEMORY;
        const HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL lock) override
    {
        if (lock)
            InterlockedIncrement(&g_locks);
        else
            InterlockedDecrement(&g_locks);
        return S_OK;
    }
};

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_module = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, kClsid))
        return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) OptiscanClassFactory();
    if (!factory)
        return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return (g_objects == 0 && g_locks == 0) ? S_OK : S_FALSE;
}

namespace
{
    LSTATUS SetStringValue(HKEY root, const std::wstring& subKey, const wchar_t* name, const std::wstring& value)
    {
        HKEY key = nullptr;
        LSTATUS status = RegCreateKeyExW(root, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr);
        if (status != ERROR_SUCCESS)
            return status;
        status = RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
        return status;
    }
}

// Enregistrement machine (installeur, compte administrateur) : classe COM et entrée AMSI.
STDAPI DllRegisterServer()
{
    wchar_t path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(g_module, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
        return HRESULT_FROM_WIN32(GetLastError());

    const std::wstring clsidKey = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + kClsidString;
    LSTATUS status = SetStringValue(HKEY_LOCAL_MACHINE, clsidKey, nullptr, L"optiSCAN AMSI Provider");
    if (status == ERROR_SUCCESS)
        status = SetStringValue(HKEY_LOCAL_MACHINE, clsidKey + L"\\InprocServer32", nullptr, path);
    if (status == ERROR_SUCCESS)
        status = SetStringValue(HKEY_LOCAL_MACHINE, clsidKey + L"\\InprocServer32", L"ThreadingModel", L"Both");
    if (status == ERROR_SUCCESS)
        status = SetStringValue(HKEY_LOCAL_MACHINE,
            std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") + kClsidString, nullptr, L"optiSCAN AMSI Provider");
    return status == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(status);
}

STDAPI DllUnregisterServer()
{
    const std::wstring providerKey = std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") + kClsidString;
    const std::wstring clsidKey = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + kClsidString;
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, providerKey.c_str(), KEY_WOW64_64KEY, 0);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, clsidKey.c_str());
    return S_OK;
}
