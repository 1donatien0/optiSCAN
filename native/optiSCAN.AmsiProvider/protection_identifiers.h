// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Miroir natif de optiSCAN.Platform/ProtectionIdentifiers.cs.
// Garder synchronisé : ProtectionIdentifiersTests échoue si les valeurs divergent.
// Ces identifiants ne contiennent pas de version produit ; seule kProtocolVersion
// évolue si le format JSON IPC change de façon incompatible.

namespace optiscan::ids {

constexpr wchar_t kProtectionPipePath[] = L"\\\\.\\pipe\\optiSCAN_Protection";
constexpr int kProtocolVersion = 1;
constexpr char kProtocolVersionJson[] = "1";

}
