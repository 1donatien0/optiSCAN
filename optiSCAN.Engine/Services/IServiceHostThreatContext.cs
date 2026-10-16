// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Services;

/// <summary>Contexte menaces pour <see cref="ServiceHostThreatHandler"/> (mode --service-host).</summary>
public interface IServiceHostThreatContext
{
    QuarantineManager Quarantine { get; }

    ScanLogManager Logger { get; }

    CloudThreatIntelService CloudThreatIntel { get; }

    /// <summary>Détections relevées par les sessions (voir <see cref="ServiceDetectionLog"/>).</summary>
    ServiceDetectionLog Detections => ServiceDetectionLog.Shared;
}
