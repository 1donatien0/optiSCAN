using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Coordinators;

/// <summary>Données nécessaires aux exports HTML/PDF (sans dépendance fenêtre WPF).</summary>
public sealed record ExportContext(
    ScanLogManager? Log,
    IEnumerable<ThreatInfo> Threats,
    IEnumerable<QuarantineEntry> Quarantine,
    Action<string, bool, bool> SetStatus);
