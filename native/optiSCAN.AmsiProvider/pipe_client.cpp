#include "pipe_client.h"
#include <windows.h>
#include <vector>

namespace optiscan::ipc {

namespace {

// Délais : AMSI est appelé en ligne par les applications ; un service qui ne répond pas
// ne doit pas les bloquer.
constexpr DWORD kIoTimeoutMs = 5000;
// Même plafond que le cadrage JSON côté .NET (ProtectionPipeJsonFraming).
constexpr size_t kMaxResponseBytes = 1024 * 1024;

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

// Le serveur légitime est l'hôte du service optiSCAN : il tourne dans la session 0.
// Un processus d'utilisateur qui occuperait le nom du pipe est refusé.
bool IsServiceSessionServer(HANDLE pipe)
{
    ULONG session = 0;
    return GetNamedPipeServerSessionId(pipe, &session) && session == 0;
}

} // namespace

bool ScanBufferViaPipe(const wchar_t* pipeName, const std::string& jsonRequest, std::string& jsonResponse)
{
    if (!WaitNamedPipeW(pipeName, kIoTimeoutMs))
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
    if (event != nullptr && IsServiceSessionServer(pipe))
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

}
