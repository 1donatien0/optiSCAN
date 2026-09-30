namespace optiSCAN.Models
{
    /// <summary>Entrées optiSCAN pour le calcul de posture (hors sondes système).</summary>
    public sealed class SecurityPostureContext
    {
        public bool ClamInstalled { get; init; }
        public bool YaraAvailable { get; init; }
        public int YaraRulesCount { get; init; }
        public bool RealTimeProtectionEnabled { get; init; }
        public bool RealTimeProtectionRunning { get; init; }
        /// <summary>Mode complémentaire : Windows Defender assure le temps réel (RTP optiSCAN coupée volontairement).</summary>
        public bool RealTimeDelegatedToDefender { get; init; }
        public DateTime? LastScanAt { get; init; }
        public bool SignatureAutoUpdateEnabled { get; init; }
    }
}
