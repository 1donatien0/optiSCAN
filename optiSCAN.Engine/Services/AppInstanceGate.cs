// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Services;

/// <summary>Mutex d'instance de l'interface, limité à la session Windows courante.</summary>
internal static class AppInstanceGate
{
    internal const string MutexName = "Local\\optiSCAN_UniqueInstance";
}
