namespace optiSCAN.Models
{
    /// <summary>
    /// Entrée d'historique d'une session de nettoyage système.
    /// </summary>
    public class CleanSession
    {
        public DateTime Date { get; set; }
        public int ItemsRemoved { get; set; }
        public long BytesFreed { get; set; }

        public string DateDisplay =>
            Date.ToString("dd/MM/yyyy HH:mm");

        public string BytesDisplay
        {
            get
            {
                if (BytesFreed >= 1_073_741_824) return $"{BytesFreed / 1_073_741_824.0:F1} Go";
                if (BytesFreed >= 1_048_576) return $"{BytesFreed / 1_048_576.0:F1} Mo";
                if (BytesFreed >= 1_024) return $"{BytesFreed / 1_024.0:F0} Ko";
                return $"{BytesFreed} o";
            }
        }
    }
}
