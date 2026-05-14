namespace optiSCAN.Models
{
    /// <summary>Durées et libellés d’affichage communs pour l’historique et les résumés de scan.</summary>
    public static class ScanDisplayFormatter
    {
        /// <summary>Formate une durée en français (ex. « 2 h 29 min 3 s », « 45 s »).</summary>
        public static string FormatDuration(TimeSpan d)
        {
            if (d < TimeSpan.Zero)
                d = TimeSpan.Zero;

            var total = (long)d.TotalSeconds;
            if (total < 1)
                return "moins d’1 s";

            var h = total / 3600;
            var m = (total % 3600) / 60;
            var s = total % 60;

            if (h > 0)
            {
                if (m == 0 && s == 0) return $"{h} h";
                if (s == 0) return $"{h} h {m} min";
                return $"{h} h {m} min {s} s";
            }

            if (m > 0)
            {
                if (s == 0) return $"{m} min";
                return $"{m} min {s} s";
            }

            return $"{s} s";
        }
    }
}
