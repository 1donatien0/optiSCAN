using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Text;

namespace optiSCAN.Services
{
    /// <summary>Une application dont une mise à jour est disponible via winget.</summary>
    public sealed class WingetPackageUpdate
    {
        public string Name { get; init; } = string.Empty;
        public string Id { get; init; } = string.Empty;
        public string InstalledVersion { get; init; } = string.Empty;
        public string AvailableVersion { get; init; } = string.Empty;
    }

    /// <summary>
    /// Mises à jour d'applications via winget (panneau Optimiser → Mises à jour).
    /// Port C# de l'utilitaire OptiWin (GUI/OptiWin-GUI.ps1) : localisation de
    /// winget.exe, parsing en colonnes de « winget upgrade », lancement des
    /// mises à niveau avec sortie streamée vers le journal de l'UI.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WingetUpdateService
    {
        private string? _wingetPath;

        /// <summary>
        /// Localise winget.exe. Ordre : alias utilisateur (fonctionne sans
        /// élévation), PATH, puis dossier WindowsApps machine (lisible seulement
        /// en admin — dernier recours).
        /// </summary>
        public string? ResolveWingetPath()
        {
            if (!string.IsNullOrEmpty(_wingetPath) && File.Exists(_wingetPath))
                return _wingetPath;

            // 1. Alias per-user (%LOCALAPPDATA%\Microsoft\WindowsApps)
            var localAlias = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\WindowsApps\winget.exe");
            if (File.Exists(localAlias))
                return _wingetPath = localAlias;

            // 2. PATH
            var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var dir in pathVar.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(dir.Trim(), "winget.exe");
                    if (File.Exists(candidate))
                        return _wingetPath = candidate;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("WingetUpdateService", $"Entrée PATH ignorée : {dir}", ex);
                }
            }

            // 3. WindowsApps machine (nécessite en pratique les droits admin)
            try
            {
                var windowsApps = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "WindowsApps");
                if (Directory.Exists(windowsApps))
                {
                    var candidate = Directory
                        .EnumerateDirectories(windowsApps, "Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe")
                        .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "winget.exe"))
                        .FirstOrDefault(File.Exists);
                    if (candidate != null)
                        return _wingetPath = candidate;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("WingetUpdateService", "Énumération WindowsApps impossible", ex);
            }

            return null;
        }

        /// <summary>
        /// Exécute « winget upgrade » et renvoie la liste des mises à jour
        /// disponibles. Renvoie une liste vide si winget est introuvable ou si
        /// la sortie n'est pas reconnue.
        /// </summary>
        public async Task<IReadOnlyList<WingetPackageUpdate>> GetAvailableUpdatesAsync(
            CancellationToken cancellationToken = default)
        {
            var winget = ResolveWingetPath();
            if (winget == null)
                return Array.Empty<WingetPackageUpdate>();

            var psi = new ProcessStartInfo
            {
                FileName = winget,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            psi.ArgumentList.Add("upgrade");
            psi.ArgumentList.Add("--include-unknown");
            psi.ArgumentList.Add("--accept-source-agreements");

            using var process = Process.Start(psi);
            if (process == null)
                return Array.Empty<WingetPackageUpdate>();

            // Lecture concurrente stdout/stderr pour éviter tout blocage de tampon.
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            _ = await stderrTask.ConfigureAwait(false);

            return ParseUpgradeOutput(stdout);
        }

        /// <summary>
        /// Parse la sortie en colonnes de « winget upgrade » (fr ou en).
        /// Les positions des colonnes sont déduites de la ligne d'en-tête
        /// (Nom/Name, Id, Version, Disponible/Available, Source).
        /// </summary>
        public static IReadOnlyList<WingetPackageUpdate> ParseUpgradeOutput(string output)
        {
            if (string.IsNullOrWhiteSpace(output))
                return Array.Empty<WingetPackageUpdate>();

            var lines = output
                .Replace("\r", string.Empty)
                .Split('\n');

            int headerIndex = -1;
            for (int i = 0; i < lines.Length; i++)
            {
                var l = lines[i];
                if ((l.StartsWith("Nom ", StringComparison.Ordinal) ||
                     l.StartsWith("Name ", StringComparison.Ordinal)) &&
                    l.Contains(" Id", StringComparison.Ordinal))
                {
                    headerIndex = i;
                    break;
                }
            }
            if (headerIndex < 0)
                return Array.Empty<WingetPackageUpdate>();

            var header = lines[headerIndex];
            int idxId = header.IndexOf("Id", StringComparison.Ordinal);
            int idxVersion = header.IndexOf("Version", StringComparison.Ordinal);
            int idxAvailable = header.IndexOf("Disponible", StringComparison.Ordinal);
            if (idxAvailable < 0)
                idxAvailable = header.IndexOf("Available", StringComparison.Ordinal);
            int idxSource = header.IndexOf("Source", StringComparison.Ordinal);
            if (idxSource < 0)
                idxSource = int.MaxValue;

            if (idxId <= 0 || idxVersion <= idxId || idxAvailable <= idxVersion)
                return Array.Empty<WingetPackageUpdate>();

            var result = new List<WingetPackageUpdate>();
            for (int i = headerIndex + 2; i < lines.Length; i++)
            {
                var l = lines[i];
                if (string.IsNullOrWhiteSpace(l))
                    break;
                // Ligne de bilan finale : « 12 mises à niveau disponibles. »
                if (char.IsDigit(l.TrimStart().FirstOrDefault()))
                    break;
                if (l.Length <= idxVersion)
                    continue;

                var id = SafeColumn(l, idxId, idxVersion);
                if (string.IsNullOrEmpty(id))
                    continue;

                result.Add(new WingetPackageUpdate
                {
                    Name = SafeColumn(l, 0, idxId),
                    Id = id,
                    InstalledVersion = SafeColumn(l, idxVersion, idxAvailable),
                    AvailableVersion = SafeColumn(l, idxAvailable, idxSource),
                });
            }
            return result;
        }

        private static string SafeColumn(string line, int start, int end)
        {
            if (start >= line.Length) return string.Empty;
            int realEnd = Math.Min(end, line.Length);
            return line[start..realEnd].Trim();
        }

        /// <summary>
        /// Met à niveau les paquets donnés (séquentiellement) en streamant la
        /// sortie vers <paramref name="onOutputLine"/>. Les installateurs
        /// déclenchent eux-mêmes l'invite UAC si nécessaire.
        /// Renvoie le nombre de paquets dont winget s'est terminé avec code 0.
        /// </summary>
        public async Task<int> UpgradePackagesAsync(
            IEnumerable<string> packageIds,
            Action<string> onOutputLine,
            CancellationToken cancellationToken = default)
        {
            var winget = ResolveWingetPath();
            if (winget == null)
                return 0;

            int succeeded = 0;
            foreach (var id in packageIds)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var exitCode = await RunWingetStreamingAsync(
                    winget,
                    new[]
                    {
                        "upgrade", "--id", id, "--include-unknown",
                        "--accept-source-agreements", "--accept-package-agreements",
                    },
                    onOutputLine,
                    cancellationToken).ConfigureAwait(false);
                if (exitCode == 0)
                    succeeded++;
            }
            return succeeded;
        }

        /// <summary>Met à niveau toutes les applications (« winget upgrade --all »).</summary>
        public async Task<int> UpgradeAllAsync(
            Action<string> onOutputLine,
            CancellationToken cancellationToken = default)
        {
            var winget = ResolveWingetPath();
            if (winget == null)
                return -1;

            return await RunWingetStreamingAsync(
                winget,
                new[]
                {
                    "upgrade", "--all", "--include-unknown",
                    "--accept-source-agreements", "--accept-package-agreements",
                },
                onOutputLine,
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<int> RunWingetStreamingAsync(
            string wingetPath,
            IReadOnlyList<string> arguments,
            Action<string> onOutputLine,
            CancellationToken cancellationToken)
        {
            var psi = new ProcessStartInfo
            {
                FileName = wingetPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (var a in arguments)
                psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };
            process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    onOutputLine(e.Data.Trim());
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    onOutputLine(e.Data.Trim());
            };

            try
            {
                if (!process.Start())
                    return -1;
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return process.ExitCode;
            }
            catch (Exception ex)
            {
                AppLogger.Error("WingetUpdateService", "Exécution winget", ex);
                return -1;
            }
        }
    }
}
