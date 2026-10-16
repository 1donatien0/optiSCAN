// SPDX-License-Identifier: GPL-3.0-or-later
// Client du tube de protection pour le fournisseur AMSI.
//
// Le fournisseur tourne dans des processus tiers : chaque appel est borné en temps, et le
// serveur est authentifié avant d'envoyer le contenu (miroir de PipeServerTrust côté .NET) :
// session 0, image optiSCAN.Host.exe ou optiSCAN.Service.exe, processus du service
// optiSCANProtection ou enfant direct de celui-ci.

#include "pipe_client.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace optiscan::ipc {

namespace {

// Attente d'une instance libre du tube : courte, le service répond en quelques millisecondes.
// Sans service installé, le tube n'existe pas et l'échec est immédiat.
constexpr DWORD kConnectTimeoutMs = 250;
// Analyse d'un contenu (clamd + YARA dans l'AppContainer) : au-delà, le contenu passe.
constexpr DWORD kIoTimeoutMs = 3000;
// Même plafond que le cadrage JSON côté .NET (ProtectionPipeJsonFraming).
constexpr size_t kMaxResponseBytes = 1024 * 1024;
constexpr wchar_t kServiceName[] = L"optiSCANProtection";

bool WaitIo(HANDLE pipe, OVERLAPPED& ov, BOOL started, DWORD& transferred)
{
    if (!started && GetLastError() != ERROR_IO_PENDING)
        return false;
    if (!GetOverlappedResultEx(pipe, &ov, &transferred, kIoTimeoutMs, FALSE))
    {
        CancelIoEx(pipe, &ov);
        GetOverlappedResult(pipe, &ov, &transferred, TRUE);
        return false;
    }
    return true;
}

DWORD QueryServiceProcessId()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return 0;
    DWORD pid = 0;
    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (service)
    {
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed))
            pid = status.dwProcessId;
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return pid;
}

DWORD QueryParentProcessId(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD parent = 0;
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == pid)
            {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return parent;
}

bool ImageNameIs(DWORD pid, const wchar_t* expected1, const wchar_t* expected2)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return false;
    wchar_t image[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    const BOOL ok = QueryFullProcessImageNameW(process, 0, image, &size);
    CloseHandle(process);
    if (!ok)
        return false;
    const wchar_t* name = wcsrchr(image, L'\\');
    name = name ? name + 1 : image;
    return _wcsicmp(name, expected1) == 0 || _wcsicmp(name, expected2) == 0;
}

bool ProcessCreatedAfter(DWORD child, DWORD parent)
{
    auto creation = [](DWORD pid, ULONGLONG& out) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return false;
        FILETIME created{}, exited{}, kernel{}, user{};
        const BOOL ok = GetProcessTimes(process, &created, &exited, &kernel, &user);
        CloseHandle(process);
        out = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        return ok != FALSE;
    };
    ULONGLONG childTime = 0, parentTime = 0;
    if (!creation(child, childTime) || !creation(parent, parentTime))
        return true; // indisponible : les autres contrôles restent appliqués
    return childTime >= parentTime;
}

// Le serveur doit être le service optiSCAN ou l'hôte qu'il a lancé : un processus quelconque
// qui occuperait le nom du tube ne reçoit pas le contenu.
bool IsTrustedServer(HANDLE pipe)
{
    ULONG session = 0;
    if (!GetNamedPipeServerSessionId(pipe, &session) || session != 0)
        return false;
    ULONG serverPid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid == 0)
        return false;
    if (!ImageNameIs(serverPid, L"optiSCAN.Host.exe", L"optiSCAN.Service.exe"))
        return false;
    const DWORD servicePid = QueryServiceProcessId();
    if (servicePid == 0)
        return false;
    if (serverPid == servicePid)
        return true;
    return QueryParentProcessId(serverPid) == servicePid && ProcessCreatedAfter(serverPid, servicePid);
}

} // namespace

bool ScanBufferViaPipe(const wchar_t* pipeName, const std::string& jsonRequest, std::string& jsonResponse)
{
    if (!WaitNamedPipeW(pipeName, kConnectTimeoutMs))
        return false;

    HANDLE pipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    bool ok = false;
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event != nullptr && IsTrustedServer(pipe))
    {
        DWORD mode = PIPE_READMODE_BYTE;
        SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

        OVERLAPPED ov{};
        ov.hEvent = event;
        DWORD transferred = 0;
        BOOL started = WriteFile(pipe, jsonRequest.data(), static_cast<DWORD>(jsonRequest.size()), nullptr, &ov);
        if (WaitIo(pipe, ov, started, transferred) && transferred == jsonRequest.size())
        {
            // Lecture jusqu'à la fermeture par le serveur, bornée en taille et en temps.
            std::string response;
            std::vector<char> buffer(8192);
            for (;;)
            {
                ResetEvent(event);
                ov = OVERLAPPED{};
                ov.hEvent = event;
                transferred = 0;
                started = ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr, &ov);
                if (!WaitIo(pipe, ov, started, transferred))
                {
                    const DWORD err = GetLastError();
                    ok = (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) && !response.empty();
                    break;
                }
                if (transferred == 0)
                {
                    ok = !response.empty();
                    break;
                }
                response.append(buffer.data(), transferred);
                if (response.size() > kMaxResponseBytes)
                    break;
            }
            if (ok)
                jsonResponse.swap(response);
        }
    }

    if (event != nullptr)
        CloseHandle(event);
    CloseHandle(pipe);
    return ok;
}

} // namespace optiscan::ipc
