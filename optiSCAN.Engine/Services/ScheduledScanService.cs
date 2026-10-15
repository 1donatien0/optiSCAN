using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère la création et la suppression d'une tâche planifiée Windows
    /// pour un scan quotidien automatique, via schtasks.exe (outil natif Windows).
    /// Aucune dépendance NuGet requise.
    /// </summary>
    public class ScheduledScanService : IScheduledScanService
    {
        private const string TaskName = "optiSCAN_DailyScan";
        private readonly string _exePath;
        private TimeSpan _scheduledTime = TimeSpan.FromHours(2);

        public ScheduledScanService()
        {
            _exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiSCAN.exe");
        }

        /// <summary>
        /// Crée la tâche planifiée pour un scan quotidien.
        /// Par défaut à 02h00 du matin.
        /// </summary>
        public bool CreateDailyScan(TimeSpan? time = null)
        {
            try
            {
                _scheduledTime = time ?? TimeSpan.FromHours(2);

                DeleteTask();

                // Définition XML plutôt que /SC DAILY : seule elle permet StartWhenAvailable.
                // Sans ce réglage, un PC en veille ou éteint à l'heure prévue sautait le scan
                // jusqu'au lendemain, indéfiniment pour un portable fermé chaque nuit.
                string? user = null;
                try { user = System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
                catch (Exception ex) { AppLogger.Debug("ScheduledScanService", "Compte courant : " + ex.Message); }

                var xml = BuildTaskXml(_exePath, _scheduledTime, DateTime.Today, user);
                var xmlPath = Path.Combine(Path.GetTempPath(), "optiSCAN_task_" + Guid.NewGuid().ToString("N") + ".xml");
                try
                {
                    // schtasks /XML attend de l'UTF-16 avec BOM.
                    File.WriteAllText(xmlPath, xml, Encoding.Unicode);
                    var psi = NewSchtasks();
                    psi.ArgumentList.Add("/Create");
                    psi.ArgumentList.Add("/TN");
                    psi.ArgumentList.Add(TaskName);
                    psi.ArgumentList.Add("/XML");
                    psi.ArgumentList.Add(xmlPath);
                    psi.ArgumentList.Add("/F");
                    var res = RunSchtasksCapture(psi);
                    if (res.ExitCode == 0)
                        return true;
                    AppLogger.Warn("ScheduledScanService", "Création XML refusée, repli /SC DAILY : " + res.CombinedOutput.Trim());
                }
                finally
                {
                    try { File.Delete(xmlPath); } catch { /* fichier temporaire */ }
                }

                return CreateDailyScanLegacy();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "Erreur création tâche planifiée", ex);
                return false;
            }
        }

        /// <summary>
        /// Recrée à la même heure une tâche existante qui n'a pas <c>StartWhenAvailable</c>
        /// (créée avant le passage à la définition XML). Sans effet si la tâche est absente.
        /// </summary>
        public bool UpgradeLegacyTask()
        {
            try
            {
                var psi = NewSchtasks();
                psi.ArgumentList.Add("/Query");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                psi.ArgumentList.Add("/XML");
                var res = RunSchtasksCapture(psi);
                if (res.ExitCode != 0 || !NeedsCatchUpUpgrade(res.StdOut, out var time))
                    return false;
                AppLogger.Info("ScheduledScanService", "Tâche planifiée mise à niveau (rattrapage au réveil)");
                return CreateDailyScan(time);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "UpgradeLegacyTask", ex);
                return false;
            }
        }

        /// <summary>Vrai si la définition n'active pas StartWhenAvailable ; renvoie l'heure prévue.</summary>
        internal static bool NeedsCatchUpUpgrade(string xml, out TimeSpan time)
        {
            time = TimeSpan.FromHours(2);
            try
            {
                var doc = XDocument.Parse(xml);
                var startWhenAvailable = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "StartWhenAvailable");
                if (startWhenAvailable != null && string.Equals(startWhenAvailable.Value.Trim(), "true", StringComparison.OrdinalIgnoreCase))
                    return false;
                var boundary = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "StartBoundary");
                if (boundary != null && DateTime.TryParse(boundary.Value.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var anchor))
                    time = new TimeSpan(anchor.Hour, anchor.Minute, 0);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static ProcessStartInfo NewSchtasks() => new()
        {
            FileName = SystemExecutables.System32("schtasks.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        /// <summary>
        /// Tâche quotidienne, moindre privilège, session interactive, rattrapée au réveil
        /// (<c>StartWhenAvailable</c>) si l'heure prévue a été manquée.
        /// </summary>
        internal static string BuildTaskXml(string exePath, TimeSpan time, DateTime today, string? userId)
        {
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var boundary = (today.Date + new TimeSpan(time.Hours, time.Minutes, 0))
                .ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);

            var principal = new XElement(ns + "Principal", new XAttribute("id", "Author"));
            if (!string.IsNullOrWhiteSpace(userId))
                principal.Add(new XElement(ns + "UserId", userId));
            principal.Add(
                new XElement(ns + "LogonType", "InteractiveToken"),
                new XElement(ns + "RunLevel", "LeastPrivilege"));

            var doc = new XDocument(
                new XElement(ns + "Task",
                    new XAttribute("version", "1.2"),
                    new XElement(ns + "RegistrationInfo",
                        new XElement(ns + "Description", "optiSCAN — analyse complète quotidienne")),
                    new XElement(ns + "Triggers",
                        new XElement(ns + "CalendarTrigger",
                            new XElement(ns + "StartBoundary", boundary),
                            new XElement(ns + "Enabled", "true"),
                            new XElement(ns + "ScheduleByDay",
                                new XElement(ns + "DaysInterval", "1")))),
                    new XElement(ns + "Principals", principal),
                    new XElement(ns + "Settings",
                        new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                        new XElement(ns + "DisallowStartIfOnBatteries", "true"),
                        new XElement(ns + "StopIfGoingOnBatteries", "false"),
                        new XElement(ns + "AllowHardTerminate", "true"),
                        new XElement(ns + "StartWhenAvailable", "true"),
                        new XElement(ns + "RunOnlyIfNetworkAvailable", "false"),
                        new XElement(ns + "AllowStartOnDemand", "true"),
                        new XElement(ns + "Enabled", "true"),
                        new XElement(ns + "Hidden", "false"),
                        new XElement(ns + "RunOnlyIfIdle", "false"),
                        new XElement(ns + "WakeToRun", "false"),
                        new XElement(ns + "ExecutionTimeLimit", "PT12H"),
                        new XElement(ns + "Priority", "7")),
                    new XElement(ns + "Actions",
                        new XAttribute("Context", "Author"),
                        new XElement(ns + "Exec",
                            new XElement(ns + "Command", exePath),
                            new XElement(ns + "Arguments", "--fullscan --quiet")))));

            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" + Environment.NewLine + doc.Root!.ToString();
        }

        /// <summary>Ancienne création en ligne de commande, sans rattrapage, si /XML échoue.</summary>
        private bool CreateDailyScanLegacy()
        {
            try
            {
                var startTime = $"{_scheduledTime.Hours:D2}:{_scheduledTime.Minutes:D2}";
                var psi = NewSchtasks();
                psi.ArgumentList.Add("/Create");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                psi.ArgumentList.Add("/TR");
                // schtasks coupe /TR au premier espace : le chemin doit porter ses propres guillemets.
                psi.ArgumentList.Add($"\"{_exePath}\" --fullscan --quiet");
                psi.ArgumentList.Add("/SC");
                psi.ArgumentList.Add("DAILY");
                psi.ArgumentList.Add("/ST");
                psi.ArgumentList.Add(startTime);
                // Moindre privilège : /RL LIMITED (jamais HIGHEST).
                psi.ArgumentList.Add("/RL");
                psi.ArgumentList.Add("LIMITED");
                psi.ArgumentList.Add("/F");

                return RunSchtasksCapture(psi).ExitCode == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "Erreur création tâche planifiée", ex);
                return false;
            }
        }

        /// <summary>
        /// Supprime la tâche planifiée.
        /// </summary>
        public bool DeleteTask()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Delete");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                psi.ArgumentList.Add("/F");
                RunSchtasksCapture(psi);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "DeleteTask", ex);
                return false;
            }
        }

        /// <summary>
        /// Vérifie si la tâche existe.
        /// </summary>
        public bool IsTaskExists()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Query");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                return RunSchtasksCapture(psi).ExitCode == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "IsTaskExists", ex);
                return false;
            }
        }

        /// <summary>
        /// Prochaine exécution : lue depuis la tâche Windows (XML / LIST) si possible,
        /// sinon dérivée de <see cref="_scheduledTime"/> (mémoire processus).
        /// </summary>
        public DateTime? GetNextRunTime()
        {
            try
            {
                if (!IsTaskExists())
                    return FallbackFromScheduledMemory();

                // 1) XML — indépendant de la locale pour l'heure du trigger
                var xmlPsi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                xmlPsi.ArgumentList.Add("/Query");
                xmlPsi.ArgumentList.Add("/TN");
                xmlPsi.ArgumentList.Add(TaskName);
                xmlPsi.ArgumentList.Add("/XML");

                var xmlRes = RunSchtasksCapture(xmlPsi);
                if (xmlRes.ExitCode == 0 && TryParseNextRunFromTaskXml(xmlRes.CombinedOutput, out var fromXml))
                    return fromXml;

                // 2) LIST /V — « Next Run Time » / « Prochaine exécution » (locale Windows)
                var listPsi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                listPsi.ArgumentList.Add("/Query");
                listPsi.ArgumentList.Add("/TN");
                listPsi.ArgumentList.Add(TaskName);
                listPsi.ArgumentList.Add("/FO");
                listPsi.ArgumentList.Add("LIST");
                listPsi.ArgumentList.Add("/V");

                var listRes = RunSchtasksCapture(listPsi);
                if (listRes.ExitCode == 0 && TryParseNextRunFromListOutput(listRes.CombinedOutput, out var fromList))
                    return fromList;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "GetNextRunTime — repli sur heure mémoire", ex);
            }

            return FallbackFromScheduledMemory();
        }

        /// <summary>
        /// Exécute la tâche immédiatement.
        /// </summary>
        public bool RunNow()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Run");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                return RunSchtasksCapture(psi).ExitCode == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "RunNow", ex);
                return false;
            }
        }

        private DateTime? FallbackFromScheduledMemory()
        {
            var next = DateTime.Today + _scheduledTime;
            if (next <= DateTime.Now)
                next = next.AddDays(1);
            return next;
        }

        internal static bool TryParseNextRunFromTaskXml(string xml, out DateTime next)
        {
            next = default;
            try
            {
                var doc = XDocument.Parse(xml);
                foreach (var el in doc.Descendants())
                {
                    if (!string.Equals(el.Name.LocalName, "StartBoundary", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var text = el.Value.Trim();
                    if (string.IsNullOrEmpty(text)) continue;

                    if (!DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var anchor)
                        && !DateTime.TryParse(text, CultureInfo.CurrentCulture, DateTimeStyles.None, out anchor))
                        continue;

                    var timeOfDay = anchor.TimeOfDay;
                    var candidate = DateTime.Today + timeOfDay;
                    if (candidate <= DateTime.Now)
                        candidate = candidate.AddDays(1);
                    next = candidate;
                    return true;
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        internal static bool TryParseNextRunFromListOutput(string text, out DateTime next)
        {
            next = default;
            foreach (var raw in text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None))
            {
                var line = raw.Trim();
                string? val = null;

                if (line.StartsWith("Next Run Time:", StringComparison.OrdinalIgnoreCase))
                    val = line["Next Run Time:".Length..].Trim();
                else if (line.StartsWith("Prochaine exécution", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0 && idx + 1 < line.Length)
                        val = line[(idx + 1)..].Trim();
                }
                else if (line.StartsWith("Heure de début suivante", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0 && idx + 1 < line.Length)
                        val = line[(idx + 1)..].Trim();
                }

                if (string.IsNullOrEmpty(val) || val.Equals("N/A", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (DateTime.TryParse(val, CultureInfo.CurrentCulture, DateTimeStyles.None, out next))
                    return true;
                if (DateTime.TryParse(val, CultureInfo.InvariantCulture, DateTimeStyles.None, out next))
                    return true;
            }

            return false;
        }

        private readonly record struct SchtasksResult(int ExitCode, string StdOut, string StdErr)
        {
            public string CombinedOutput
            {
                get
                {
                    var sb = new StringBuilder();
                    if (!string.IsNullOrEmpty(StdOut)) sb.AppendLine(StdOut);
                    if (!string.IsNullOrEmpty(StdErr)) sb.AppendLine(StdErr);
                    return sb.ToString();
                }
            }
        }

        private static SchtasksResult RunSchtasksCapture(ProcessStartInfo psi)
        {
            using var p = Process.Start(psi)
                ?? throw new InvalidOperationException("Impossible de démarrer schtasks.exe");

            // Lecture CONCURRENTE stdout + stderr : la lecture séquentielle
            // (ReadToEnd puis ReadToEnd) peut bloquer indéfiniment si le process
            // remplit le buffer interne stderr pendant qu'on attend la fin de
            // stdout, et vice-versa (deadlock documenté par Microsoft).
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            bool finished = Task.WhenAll(stdoutTask, stderrTask)
                .Wait(TimeSpan.FromSeconds(15));
            if (!finished)
            {
                try { p.Kill(entireProcessTree: true); }
                catch (Exception ex)
                {
                    AppLogger.Warn("ScheduledScanService", "schtasks timeout — Kill", ex);
                }
            }

            p.WaitForExit(1_000);

            return new SchtasksResult(
                p.ExitCode,
                stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : string.Empty,
                stderrTask.IsCompletedSuccessfully ? stderrTask.Result : string.Empty);
        }
    }
}
