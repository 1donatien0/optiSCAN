// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>Évalue la note de posture sécurité (/100) et les contrôles associés.</summary>
    public interface ISecurityPostureService
    {
        SecurityPostureReport Evaluate(SecurityPostureContext context);
    }
}
