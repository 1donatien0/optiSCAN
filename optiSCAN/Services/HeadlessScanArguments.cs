namespace optiSCAN.Services
{
    /// <summary>Arguments de ligne de commande pour scans sans interface (tâche planifiée).</summary>
    public static class HeadlessScanArguments
    {
        public const string FullScan = "--fullscan";
        public const string QuickScan = "--quickscan";
        public const string Quiet = "--quiet";

        public enum Mode { None, FullScan, QuickScan }

        public static Mode ParseMode(IReadOnlyList<string> args)
        {
            foreach (var a in args)
            {
                if (string.Equals(a, FullScan, StringComparison.OrdinalIgnoreCase))
                    return Mode.FullScan;
                if (string.Equals(a, QuickScan, StringComparison.OrdinalIgnoreCase))
                    return Mode.QuickScan;
            }
            return Mode.None;
        }

        public static bool IsQuiet(IReadOnlyList<string> args) =>
            args.Any(a => string.Equals(a, Quiet, StringComparison.OrdinalIgnoreCase));
    }
}
