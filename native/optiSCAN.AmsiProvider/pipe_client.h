// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>

namespace optiscan::ipc {

bool ScanBufferViaPipe(const wchar_t* pipeName, const std::string& jsonRequest, std::string& jsonResponse);

}
