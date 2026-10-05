namespace optiSCAN.Services
{
    /// <summary>Arguments de ligne de commande pour scans sans interface (tâche planifiée).</summary>
    public static class HeadlessScanArguments
    {
        public const string FullScan = "--fullscan";
        public const string QuickScan = "--quickscan";
        public const string Quiet = "--quiet";
        public const string Guard = "--guard";
        public const string Watchdog = "--watchdog";
        public const string ServiceHost = "--service-host";
        public const string DefenderExclusions = "--defender-exclusions";
        public const string RemoveDefenderExclusions = "--remove-defender-exclusions";
        public const string ApplyTweaks = "--apply-tweaks";
        public const string ClamdBroker = "--clamd-broker";
        public const string ClamdRelay = "--clamd-relay";
        public const string ClamdStub = "--clamd-stub";
        /// <summary>Lancé par la tâche de démarrage des versions antérieures : retire cette tâche (fonction supprimée).</summary>
        public const string ClearDefenderHistory = "--clear-defender-history";
        public const string CleanupLegacyDefenderExclusions = "--cleanup-legacy-defender-exclusions";
        public const string PushHostPolicy = "--push-host-policy";
        public const string ServiceQuarantine = "--service-quarantine";

        public enum Mode { None, FullScan, QuickScan, Guard, Watchdog, ServiceHost, DefenderExclusions, RemoveDefenderExclusions, ApplyTweaks, ClamdBroker, ClamdRelay, ClamdStub, ClearDefenderHistory, CleanupLegacyDefenderExclusions, PushHostPolicy, ServiceQuarantine }

        public static Mode ParseMode(IReadOnlyList<string> args)
        {
            foreach (var a in args)
            {
                if (string.Equals(a, Watchdog, StringComparison.OrdinalIgnoreCase))
                    return Mode.Watchdog;
                if (string.Equals(a, Guard, StringComparison.OrdinalIgnoreCase))
                    return Mode.Guard;
                if (string.Equals(a, ServiceHost, StringComparison.OrdinalIgnoreCase))
                    return Mode.ServiceHost;
                if (string.Equals(a, DefenderExclusions, StringComparison.OrdinalIgnoreCase))
                    return Mode.DefenderExclusions;
                if (string.Equals(a, RemoveDefenderExclusions, StringComparison.OrdinalIgnoreCase))
                    return Mode.RemoveDefenderExclusions;
                if (string.Equals(a, ApplyTweaks, StringComparison.OrdinalIgnoreCase))
                    return Mode.ApplyTweaks;
                if (string.Equals(a, ClamdBroker, StringComparison.OrdinalIgnoreCase))
                    return Mode.ClamdBroker;
                if (string.Equals(a, ClamdRelay, StringComparison.OrdinalIgnoreCase))
                    return Mode.ClamdRelay;
                if (string.Equals(a, ClamdStub, StringComparison.OrdinalIgnoreCase))
                    return Mode.ClamdStub;
                if (string.Equals(a, ClearDefenderHistory, StringComparison.OrdinalIgnoreCase))
                    return Mode.ClearDefenderHistory;
                if (string.Equals(a, CleanupLegacyDefenderExclusions, StringComparison.OrdinalIgnoreCase))
                    return Mode.CleanupLegacyDefenderExclusions;
                if (string.Equals(a, PushHostPolicy, StringComparison.OrdinalIgnoreCase))
                    return Mode.PushHostPolicy;
                if (string.Equals(a, ServiceQuarantine, StringComparison.OrdinalIgnoreCase))
                    return Mode.ServiceQuarantine;
                if (string.Equals(a, FullScan, StringComparison.OrdinalIgnoreCase))
                    return Mode.FullScan;
                if (string.Equals(a, QuickScan, StringComparison.OrdinalIgnoreCase))
                    return Mode.QuickScan;
            }
            return Mode.None;
        }

        public static bool IsQuiet(IReadOnlyList<string> args) =>
            args.Any(a => string.Equals(a, Quiet, StringComparison.OrdinalIgnoreCase));

        /// <summary>Valeur qui suit <c>--push-host-policy</c>.</summary>
        public static string? GetPushHostPolicyArgument(IReadOnlyList<string> args)
        {
            for (var i = 0; i < args.Count - 1; i++)
            {
                if (string.Equals(args[i], PushHostPolicy, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            }

            return null;
        }

        /// <summary>Identifiants après <c>--apply-tweaks</c>, séparés par des virgules.</summary>
        public static IReadOnlyList<string> ParseTweakIds(IReadOnlyList<string> args)
        {
            for (var i = 0; i < args.Count; i++)
            {
                if (!string.Equals(args[i], ApplyTweaks, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (i + 1 >= args.Count)
                    return Array.Empty<string>();
                return args[i + 1]
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }

            return Array.Empty<string>();
        }

        public static bool TryParseClamdBroker(IReadOnlyList<string> args, out string pipe, out int port, out int parentPid, out string allowedSid)
        {
            pipe = string.Empty;
            port = 0;
            parentPid = 0;
            allowedSid = string.Empty;
            for (var i = 0; i < args.Count; i++)
            {
                if (!string.Equals(args[i], ClamdBroker, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (i + 4 >= args.Count)
                    return false;
                pipe = args[i + 1];
                return int.TryParse(args[i + 2], out port)
                    && int.TryParse(args[i + 3], out parentPid)
                    && !string.IsNullOrWhiteSpace(pipe)
                    && (allowedSid = args[i + 4]).StartsWith("S-1-", StringComparison.Ordinal);
            }
            return false;
        }

        public static bool TryParseClamdRelay(IReadOnlyList<string> args, out int port, out int parentPid, out string controlFile)
        {
            port = 0;
            parentPid = 0;
            controlFile = string.Empty;
            for (var i = 0; i < args.Count; i++)
            {
                if (!string.Equals(args[i], ClamdRelay, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (i + 3 >= args.Count)
                    return false;
                controlFile = args[i + 3];
                return int.TryParse(args[i + 1], out port)
                    && int.TryParse(args[i + 2], out parentPid)
                    && !string.IsNullOrWhiteSpace(controlFile);
            }
            return false;
        }

        public static bool TryParseClamdStub(IReadOnlyList<string> args, out int port)
        {
            port = 0;
            for (var i = 0; i < args.Count; i++)
            {
                if (!string.Equals(args[i], ClamdStub, StringComparison.OrdinalIgnoreCase))
                    continue;
                return i + 1 < args.Count && int.TryParse(args[i + 1], out port) && port is > 0 and < 65536;
            }
            return false;
        }
    }
}
